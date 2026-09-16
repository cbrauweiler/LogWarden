<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Windows;

use DateTimeImmutable;
use DateTimeZone;
use LogWarden\Event\Event;
use LogWarden\Event\EventResult;
use LogWarden\Event\NormalizerInterface;
use LogWarden\Event\SourceType;

/**
 * Turns one NDJSON record from the WinRM collector into an Event.
 *
 * ### Why the raw message is written here rather than taken from Windows
 *
 * Windows renders event 4624 as roughly 1.5 KB, of which about 1.2 KB is a
 * fixed essay explaining what logon types are — repeated identically on every
 * single logon. Storing it would put that essay in the full-text index
 * hundreds of thousands of times and make every search for a common word
 * match every logon ever recorded.
 *
 * The one-line summary built below carries the same facts in the same
 * language regardless of the domain controller's locale, and it is the line
 * the search view actually shows. The original message stays available per
 * source via `include_message`, in `details.win_message`.
 */
final class AdNormalizer implements NormalizerInterface
{
    /**
     * Which field names the acting principal.
     *
     * For a logon, `TargetUserName` is the person; for account management it
     * is the account being *changed*, and `SubjectUserName` is whoever changed
     * it. Getting this backwards would file "Administrator added someone to
     * Domain Admins" under the administrator, and the question afterwards is
     * always who was added.
     */
    private const SUBJECT_IS_PRINCIPAL = [4672, 1102, 4719, 4739, 4713, 4716, 4906];

    private readonly SourceType $sourceType;

    public function __construct(
        private readonly string $sourceHost,
        private readonly string $channel = 'Security',
        ?SourceType $sourceType = null,
        private readonly bool $includeComputerAccounts = false,
        private readonly bool $includeSystemAccounts = false,
    ) {
        // Not a default parameter value: SourceType::of() is a method call and
        // the set it validates against is only known once the plugins are read.
        $this->sourceType = $sourceType ?? SourceType::of('ad');
    }

    public function supports(string $raw, array $context = []): bool
    {
        $trimmed = ltrim($raw);

        return $trimmed !== '' && $trimmed[0] === '{' && str_contains($trimmed, '"r"');
    }

    /** @return list<Event> */
    public function normalize(string $raw, array $context = []): array
    {
        $record = json_decode(trim($raw), true);
        if (!is_array($record) || !isset($record['i'], $record['t'], $record['r'])) {
            return [];
        }

        if (!is_numeric($record['i']) || !is_string($record['t'])) {
            return [];
        }

        $id      = (int) $record['i'];
        $data    = is_array($record['d'] ?? null) ? $record['d'] : [];
        $meaning = AdEventCatalog::describe($id);

        // An unknown id is still stored — with its number as the label. The
        // alternative, dropping it, would mean a channel filter that let
        // something through silently produced nothing at all.
        $label    = $meaning['label']    ?? ('Ereignis ' . $id);
        $category = $meaning['category'] ?? 'sonstige';

        $ts = $this->timestamp((string) $record['t']);
        if ($ts === null) {
            return [];
        }

        $principal = $this->principal($id, $category, $data);
        $actor     = Event::normaliseUsername($this->field($data, 'SubjectUserName'));

        if ($this->shouldDrop($principal, $actor)) {
            return [];
        }

        $srcIp  = Event::normaliseIp($this->field($data, 'IpAddress'))
            ?? Event::normaliseIp($this->field($data, 'ClientAddress'))
            ?? Event::normaliseIp($this->field($data, 'Source'));

        $result  = $this->result($id, $data, $meaning['result'] ?? null);
        $details = $this->details($id, $category, $label, $data, $record, $actor);

        return [new Event(
            ts:          $ts,
            sourceType:  $this->sourceType,
            sourceHost:  $this->host($record),
            eventType:   (string) $id,
            rawMessage:  $this->summary($id, $label, $category, $principal, $actor, $srcIp, $data, $result),
            username:    $principal,
            srcIp:       $srcIp,
            dstIp:       null,
            result:      $result,
            details:     $details,
            dedupKey:    $this->dedupKey($record),
        )];
    }

    /**
     * Identity of the record on its host.
     *
     * EventRecordID is assigned by the channel and never reused while the log
     * exists, which makes re-reading an overlapping window free: the same
     * record produces the same key and the insert is discarded. That is what
     * allows the collector to overlap deliberately rather than trusting clocks.
     */
    private function dedupKey(array $record): string
    {
        return substr(hash('sha256', implode("\0", [
            'winrm',
            strtolower($this->host($record)),
            strtolower($this->channel),
            (string) $record['r'],
        ])), 0, 40);
    }

    private function host(array $record): string
    {
        $host = trim((string) ($record['c'] ?? ''));

        return $host === '' ? $this->sourceHost : Event::sanitiseText($host, 255);
    }

    private function principal(int $id, string $category, array $data): ?string
    {
        if (in_array($id, self::SUBJECT_IS_PRINCIPAL, true)) {
            return Event::normaliseUsername($this->field($data, 'SubjectUserName'));
        }

        // Group membership events put the *group* in TargetUserName and the
        // member in MemberName. Filing them under the group would answer
        // "what happened to Domain Admins" but never "what is pweber a member
        // of", and the second question is the one asked after an incident.
        //
        // MemberName is a distinguished name, so the principal here is a
        // display name ("Peter Weber") rather than a logon name. It therefore
        // will not line up with 4624 for the same person; details.member_sid
        // is the identity that does.
        if ($category === AdEventCatalog::CAT_GROUP) {
            $member = self::commonName($this->field($data, 'MemberName'));
            if ($member !== null) {
                return Event::sanitiseText($member, 256);
            }
        }

        return Event::normaliseUsername($this->field($data, 'TargetUserName'))
            ?? Event::normaliseUsername($this->field($data, 'SubjectUserName'));
    }

    /**
     * Machine and service accounts are dropped by default.
     *
     * On a domain controller they are the majority of the Security channel and
     * they never answer a question anyone asks. Keeping them would not merely
     * cost storage: every "top accounts" view would be a list of computers.
     */
    private function shouldDrop(?string $principal, ?string $actor): bool
    {
        if ($principal === null) {
            return false;
        }

        if (!$this->includeComputerAccounts && WindowsCodes::isComputerAccount($principal)) {
            return true;
        }

        if (!$this->includeSystemAccounts && WindowsCodes::isSystemAccount($principal)
            && !WindowsCodes::isComputerAccount($actor)) {
            return true;
        }

        return false;
    }

    /**
     * Some events carry the outcome in a field rather than in their id: 4768
     * and 4776 are logged for success and failure alike, and only the status
     * code tells them apart.
     */
    private function result(int $id, array $data, ?EventResult $fromCatalogue): ?EventResult
    {
        if ($fromCatalogue !== null) {
            return $fromCatalogue;
        }

        $status = $this->field($data, 'Status') ?? $this->field($data, 'ResultCode');
        if ($status === null) {
            return EventResult::Info;
        }

        $normalised = strtolower(trim($status));
        $isSuccess  = $normalised === '0x0' || $normalised === '0x00000000' || $normalised === '0';

        return $isSuccess ? EventResult::Success : EventResult::Fail;
    }

    /** @return array<string, mixed> */
    private function details(int $id, string $category, string $label, array $data, array $record, ?string $actor): array
    {
        $details = [
            'label'    => $label,
            'category' => $category,
            'channel'  => $this->channel,
            'record_id' => (int) $record['r'],
        ];

        if (!empty($record['p'])) {
            $details['provider'] = Event::sanitiseText((string) $record['p'], 128);
        }

        if ($actor !== null) {
            $details['actor'] = $actor;
        }

        $logonType = WindowsCodes::logonType($this->field($data, 'LogonType'));
        if ($logonType !== null) {
            $details['logon_type']      = (int) $this->field($data, 'LogonType');
            $details['logon_type_text'] = $logonType;
        }

        $reason = $this->failureReason($id, $data);
        if ($reason !== null) {
            $details['reason'] = $reason;
        }

        // Event 4740 reuses TargetDomainName for the computer that caused the
        // lockout. Storing it as a domain would put "WS-PWEBER" in a field
        // every other event fills with "CORP" — and hide the single most
        // useful fact the event carries: which machine holds the stale
        // credential.
        if ($id === 4740) {
            $caller = $this->field($data, 'TargetDomainName');
            if ($caller !== null) {
                $details['lockout_source'] = Event::sanitiseText($caller, 255);
            }
        }

        foreach ([
            'WorkstationName' => 'workstation',
            'Workstation'     => 'workstation',
            'TargetDomainName' => 'target_domain',
            'SubjectDomainName' => 'actor_domain',
            'ProcessName'     => 'process',
            'AuthenticationPackageName' => 'auth_package',
            'LogonProcessName' => 'logon_process',
            'ServiceName'     => 'service',
            'TargetSid'       => 'target_sid',
            'MemberName'      => 'member_dn',
            'MemberSid'       => 'member_sid',
            'ObjectDN'        => 'object_dn',
            'ObjectClass'     => 'object_class',
            'AttributeLDAPDisplayName' => 'attribute',
            'AttributeValue'  => 'attribute_value',
        ] as $source => $target) {
            if ($source === 'TargetDomainName' && $id === 4740) {
                continue;
            }

            $value = $this->field($data, $source);
            if ($value !== null && !isset($details[$target])) {
                $details[$target] = Event::sanitiseText($value, 512);
            }
        }

        // The group a member was added to or removed from. Windows writes the
        // group in TargetUserName for these, which is also where the principal
        // comes from — so it is named explicitly rather than left ambiguous.
        if ($category === AdEventCatalog::CAT_GROUP) {
            $group = $this->field($data, 'TargetUserName');
            if ($group !== null) {
                $details['group'] = Event::sanitiseText($group, 256);
            }
            $groupSid = $this->field($data, 'TargetSid');
            if ($groupSid !== null) {
                $details['group_sid'] = $groupSid;
            }
        }

        $privileges = WindowsCodes::notablePrivileges($this->field($data, 'PrivilegeList'));
        if ($privileges !== []) {
            $details['privileges'] = $privileges;
        }

        if (!empty($record['m'])) {
            $details['win_message'] = Event::sanitiseText((string) $record['m'], 4096);
        }

        return $details;
    }

    private function failureReason(int $id, array $data): ?string
    {
        if ($id === 4771 || $id === 4768) {
            return WindowsCodes::kerberos($this->field($data, 'Status'));
        }

        // SubStatus carries the specific reason; Status is the generic
        // "logon failure" for almost every 4625, which is why reading only
        // Status makes every failed logon look identical.
        return WindowsCodes::status($this->field($data, 'SubStatus'))
            ?? WindowsCodes::status($this->field($data, 'Status'));
    }

    /**
     * The line that is stored, indexed and shown.
     *
     * @param array<string, mixed> $data
     */
    private function summary(
        int $id,
        string $label,
        string $category,
        ?string $principal,
        ?string $actor,
        ?string $srcIp,
        array $data,
        ?EventResult $result,
    ): string {
        $parts = [$label];

        if ($category === AdEventCatalog::CAT_GROUP) {
            $member = $principal ?? '?';
            $group  = $this->field($data, 'TargetUserName') ?? '?';
            $parts[] = sprintf('%s in "%s"', $member, $group);
            if ($actor !== null) {
                $parts[] = 'durch ' . $actor;
            }

            return $this->join($id, $parts);
        }

        if ($id === 4740) {
            $parts[] = $principal ?? '?';
            $caller  = $this->field($data, 'TargetDomainName');
            $parts[] = $caller === null ? '' : ('— ausgelöst von ' . $caller);

            return $this->join($id, array_values(array_filter($parts)));
        }

        if ($principal !== null) {
            $parts[] = $principal;
        }

        if ($srcIp !== null) {
            $parts[] = 'von ' . $srcIp;
        } else {
            // 4776 names the field `Workstation`, every logon event names it
            // `WorkstationName`. Same fact, two spellings.
            $workstation = $this->field($data, 'WorkstationName') ?? $this->field($data, 'Workstation');
            if ($workstation !== null) {
                $parts[] = 'von ' . $workstation;
            }
        }

        $logonType = WindowsCodes::logonType($this->field($data, 'LogonType'));
        if ($logonType !== null) {
            $parts[] = '(' . $logonType . ')';
        }

        if ($result === EventResult::Fail) {
            $reason = $this->failureReason($id, $data);
            if ($reason !== null) {
                $parts[] = '— ' . $reason;
            }
        }

        if ($actor !== null && $actor !== $principal && $category !== AdEventCatalog::CAT_LOGON
            && !WindowsCodes::isComputerAccount($actor)) {
            $parts[] = 'durch ' . $actor;
        }

        return $this->join($id, $parts);
    }

    /** @param list<string> $parts */
    private function join(int $id, array $parts): string
    {
        // The id goes into the text as well: an administrator who knows the
        // number should be able to type it into the search box and find the
        // event, without having to know that it also lives in event_type.
        return Event::sanitiseText(sprintf('[%d] %s', $id, implode(' ', $parts)), 2000);
    }

    /** `CN=Peter Weber,OU=Users,DC=corp,DC=local` → `Peter Weber` */
    private static function commonName(?string $dn): ?string
    {
        if ($dn === null || trim($dn) === '' || trim($dn) === '-') {
            return null;
        }

        if (preg_match('/^CN=((?:[^,\\\\]|\\\\.)+)/i', trim($dn), $m) === 1) {
            return str_replace(['\\,', '\\='], [',', '='], $m[1]);
        }

        return trim($dn);
    }

    private function field(array $data, string $name): ?string
    {
        $value = $data[$name] ?? null;
        if (!is_scalar($value)) {
            return null;
        }

        $value = trim((string) $value);

        return ($value === '' || $value === '-') ? null : $value;
    }

    /**
     * Parses PowerShell's round-trip ("o") format.
     *
     * Two traps. First, .NET writes *seven* fractional digits — 100-nanosecond
     * ticks — where DateTimeImmutable::createFromFormat's `u` expects six, so
     * the fraction is truncated before parsing rather than handed over whole.
     *
     * Second, there is deliberately no open-ended `new DateTimeImmutable($v)`
     * fallback. That constructor accepts far more than a timestamp: the string
     * 'y' is a valid military time-zone abbreviation and silently yields the
     * current time. A record with a corrupt timestamp would then be stored
     * dated to the moment it was collected — and nothing about the result
     * would look wrong, which in a security log is worse than losing it.
     */
    private function timestamp(string $value): ?DateTimeImmutable
    {
        $matched = preg_match(
            '/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:?\d{2})?$/',
            trim($value),
            $m,
        );

        if ($matched !== 1) {
            return null;
        }

        $fraction = str_pad(substr($m[3] ?? '', 0, 6), 6, '0');
        $offset   = $m[4] ?? 'Z';
        $offset   = ($offset === 'Z' || $offset === '') ? '+0000' : str_replace(':', '', $offset);

        $parsed = DateTimeImmutable::createFromFormat(
            'Y-m-d H:i:s.uO',
            sprintf('%s %s.%s%s', $m[1], $m[2], $fraction, $offset),
            new DateTimeZone('UTC'),
        );

        return $parsed === false ? null : $parsed->setTimezone(new DateTimeZone('UTC'));
    }
}
