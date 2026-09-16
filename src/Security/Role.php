<?php

declare(strict_types=1);

namespace LogWarden\Security;

/**
 * The internal permission levels. AD groups and accounts are mapped onto
 * these; nothing outside this file decides what a role may do.
 */
enum Role: string
{
    case Admin    = 'admin';
    case Analyst  = 'analyst';
    case Readonly = 'readonly';

    public function label(): string
    {
        return match ($this) {
            self::Admin    => 'Administrator',
            self::Analyst  => 'Analyst',
            self::Readonly => 'Nur lesend',
        };
    }

    public function description(): string
    {
        return match ($this) {
            self::Admin    => 'Vollzugriff einschließlich Quellen, Regeln, Benachrichtigungen und Benutzerverwaltung.',
            self::Analyst  => 'Suche und Dashboard, Alerts quittieren und schließen, Regeln einsehen und testen.',
            self::Readonly => 'Dashboard und Suche. Keine Änderungen.',
        };
    }

    /**
     * Higher wins when an account matches several mappings — membership in
     * both SOC-Analysten and SOC-Admins grants admin, not the lesser of the two.
     */
    public function rank(): int
    {
        return match ($this) {
            self::Admin    => 30,
            self::Analyst  => 20,
            self::Readonly => 10,
        };
    }

    /** @return list<string> */
    public function permissions(): array
    {
        $readonly = [
            Permission::DASHBOARD_VIEW,
            Permission::SEARCH_VIEW,
            Permission::EVENT_VIEW,
            Permission::EXPORT_EVENTS,
            Permission::ALERT_VIEW,
            Permission::PROFILE_SELF,
        ];

        $analyst = [...$readonly, Permission::ALERT_ACK, Permission::RULE_VIEW, Permission::RULE_TEST];

        return match ($this) {
            self::Readonly => $readonly,
            self::Analyst  => $analyst,
            self::Admin    => [
                ...$analyst,
                Permission::RULE_EDIT,
                Permission::SOURCE_MANAGE,
                Permission::NOTIFY_MANAGE,
                Permission::BRANDING_MANAGE,
                Permission::USER_MANAGE,
                Permission::AUDIT_VIEW,
            ],
        };
    }

    public function can(string $permission): bool
    {
        return in_array($permission, $this->permissions(), true);
    }

    public static function tryFromName(?string $value): ?self
    {
        return $value === null ? null : self::tryFrom(strtolower(trim($value)));
    }

    /** @return list<self> */
    public static function all(): array
    {
        return [self::Admin, self::Analyst, self::Readonly];
    }
}
