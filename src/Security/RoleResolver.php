<?php

declare(strict_types=1);

namespace LogWarden\Security;

use LogWarden\Core\Db;

/**
 * Decides which internal permission level an account gets.
 *
 * Mappings come from `ldap_role_map` and address either a directory group or a
 * single account. Both exist because both are needed: groups for the team, a
 * single account for the one auditor who does not justify a new AD group —
 * and waiting for one is how people end up sharing a login.
 */
final class RoleResolver
{
    public function __construct(private readonly Db $db)
    {
    }

    /**
     * @param list<string> $groups Group DNs as the directory reported them
     * @return array{role: Role|null, matched_by: string|null}
     */
    public function resolve(string $username, array $groups): array
    {
        $mappings = $this->db->fetchAll(
            'SELECT subject_type, subject, role::text AS role, priority
               FROM ldap_role_map
              WHERE enabled
              ORDER BY priority DESC, id'
        );

        if ($mappings === []) {
            return ['role' => null, 'matched_by' => null];
        }

        // Accept both the full distinguished name and the bare group name.
        // Administrators think in terms of "SOC-Admins", not
        // "CN=SOC-Admins,OU=Groups,DC=corp,DC=local", and typing the DN by
        // hand is how a mapping silently fails to match.
        $haystack = [];
        foreach ($groups as $dn) {
            $haystack[mb_strtolower(trim($dn))] = true;
            $cn = self::commonName($dn);
            if ($cn !== null) {
                $haystack[mb_strtolower($cn)] = true;
            }
        }

        $best      = null;
        $bestScore = -1;
        $matchedBy = null;

        foreach ($mappings as $mapping) {
            $subject = mb_strtolower(trim((string) $mapping['subject']));
            $role    = Role::tryFromName((string) $mapping['role']);

            if ($role === null || $subject === '') {
                continue;
            }

            $matches = $mapping['subject_type'] === 'user'
                ? $subject === mb_strtolower(trim($username))
                : isset($haystack[$subject]);

            if (!$matches) {
                continue;
            }

            // Priority first, then the stronger role: someone in both
            // SOC-Analysten and SOC-Admins is an admin, not an analyst.
            $score = ((int) $mapping['priority'] * 100) + $role->rank();

            if ($score > $bestScore) {
                $bestScore = $score;
                $best      = $role;
                $matchedBy = sprintf(
                    '%s: %s',
                    $mapping['subject_type'] === 'user' ? 'Konto' : 'Gruppe',
                    $mapping['subject'],
                );
            }
        }

        return ['role' => $best, 'matched_by' => $matchedBy];
    }

    /**
     * First RDN of a distinguished name, which for a group is its name.
     * Escaped commas inside a value must not split the name.
     */
    public static function commonName(string $dn): ?string
    {
        $dn = trim($dn);

        if ($dn === '') {
            return null;
        }

        if (!str_contains($dn, '=')) {
            return $dn;
        }

        $value  = substr($dn, strpos($dn, '=') + 1);
        $length = strlen($value);
        $out    = '';

        for ($i = 0; $i < $length; $i++) {
            if ($value[$i] === '\\' && $i + 1 < $length) {
                $out .= $value[$i + 1];
                $i++;
                continue;
            }
            if ($value[$i] === ',') {
                break;
            }
            $out .= $value[$i];
        }

        $out = trim($out);

        return $out === '' ? null : $out;
    }
}
