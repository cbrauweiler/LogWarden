<?php

declare(strict_types=1);

namespace LogWarden\Security;

/**
 * Every capability the frontend gates on.
 *
 * Named after what a person does, not after a route: the same permission
 * covers the page and the action behind it, so a new route cannot accidentally
 * end up ungated.
 */
final class Permission
{
    public const DASHBOARD_VIEW  = 'dashboard.view';
    public const SEARCH_VIEW     = 'search.view';
    public const EVENT_VIEW      = 'event.view';
    public const EXPORT_EVENTS   = 'event.export';

    public const ALERT_VIEW      = 'alert.view';
    public const ALERT_ACK       = 'alert.ack';

    public const RULE_VIEW       = 'rule.view';
    public const RULE_TEST       = 'rule.test';
    public const RULE_EDIT       = 'rule.edit';

    public const SOURCE_MANAGE   = 'source.manage';
    public const NOTIFY_MANAGE   = 'notify.manage';
    public const BRANDING_MANAGE = 'branding.manage';
    public const USER_MANAGE     = 'user.manage';
    public const AUDIT_VIEW      = 'audit.view';

    public const PROFILE_SELF    = 'profile.self';

    /** Human labels for the profile page's permission list. */
    public const LABELS = [
        self::DASHBOARD_VIEW  => 'Dashboard ansehen',
        self::SEARCH_VIEW     => 'Events durchsuchen',
        self::EVENT_VIEW      => 'Event-Details ansehen',
        self::EXPORT_EVENTS   => 'Suchergebnisse als CSV exportieren',
        self::ALERT_VIEW      => 'Alerts ansehen',
        self::ALERT_ACK       => 'Alerts quittieren und schließen',
        self::RULE_VIEW       => 'Regeln einsehen',
        self::RULE_TEST       => 'Regeln testen',
        self::RULE_EDIT       => 'Regeln bearbeiten',
        self::SOURCE_MANAGE   => 'Ingestion-Quellen verwalten',
        self::NOTIFY_MANAGE   => 'Benachrichtigungen verwalten',
        self::BRANDING_MANAGE => 'Corporate Identity ändern',
        self::USER_MANAGE     => 'Benutzer und Berechtigungen verwalten',
        self::AUDIT_VIEW      => 'Änderungsprotokoll einsehen',
        self::PROFILE_SELF    => 'Eigenes Profil und Passwort',
    ];
}
