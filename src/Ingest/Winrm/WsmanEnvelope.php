<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Winrm;

/**
 * Builds the SOAP envelopes of MS-WSMV, the Windows Remote Shell protocol.
 *
 * The shapes below follow [MS-WSMV] §3.1.4. They are deliberately written as
 * templates rather than assembled through DOM: the wire format is the thing
 * being debugged when a Windows host answers with a fault, and a template can
 * be diffed against the specification line by line. Everything interpolated
 * goes through {@see esc}.
 */
final class WsmanEnvelope
{
    public const NS_SOAP     = 'http://www.w3.org/2003/05/soap-envelope';
    public const NS_ADDR     = 'http://schemas.xmlsoap.org/ws/2004/08/addressing';
    public const NS_WSMAN    = 'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd';
    public const NS_SHELL    = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell';
    public const NS_MSWSMAN  = 'http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd';
    public const NS_FAULT    = 'http://schemas.microsoft.com/wbem/wsman/1/wsmanfault';

    public const URI_SHELL_CMD = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd';

    private const A_CREATE  = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Create';
    private const A_DELETE  = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete';
    private const A_COMMAND = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command';
    private const A_RECEIVE = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive';
    private const A_SIGNAL  = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal';

    public const SIGNAL_TERMINATE = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate';

    public function __construct(
        private readonly string $endpoint,
        private readonly int $maxEnvelopeSize = 512000,
        private readonly int $operationTimeout = 60,
        private readonly string $locale = 'en-US',
    ) {
    }

    /**
     * Opens a cmd.exe shell on the remote host.
     *
     * The code page is forced to 65001 (UTF-8). Without it the shell answers
     * in the host's OEM code page — on a German Windows that is CP850, where
     * every umlaut in an account name arrives as a different byte than the one
     * PostgreSQL is about to be told is UTF-8.
     */
    public function createShell(?string $workingDirectory = null, int $idleTimeout = 180): string
    {
        $body = '<rsp:Shell xmlns:rsp="' . self::NS_SHELL . '">'
            . '<rsp:InputStreams>stdin</rsp:InputStreams>'
            . '<rsp:OutputStreams>stdout stderr</rsp:OutputStreams>'
            . '<rsp:IdleTimeOut>PT' . $idleTimeout . '.000S</rsp:IdleTimeOut>';

        if ($workingDirectory !== null) {
            $body .= '<rsp:WorkingDirectory>' . self::esc($workingDirectory) . '</rsp:WorkingDirectory>';
        }

        $body .= '</rsp:Shell>';

        $options = '<w:OptionSet>'
            . '<w:Option Name="WINRS_NOPROFILE">TRUE</w:Option>'
            . '<w:Option Name="WINRS_CODEPAGE">65001</w:Option>'
            . '</w:OptionSet>';

        return $this->wrap(self::A_CREATE, self::URI_SHELL_CMD, $body, '', $options);
    }

    /**
     * Starts a command inside an open shell.
     *
     * WINRS_SKIP_CMD_SHELL runs the executable directly instead of through
     * `cmd.exe /c`. That removes one layer of cmd quoting from a command line
     * that already carries a base64 blob — and cmd's quoting rules are the
     * classic source of "works locally, fails remotely".
     *
     * @param list<string> $arguments
     */
    public function command(string $shellId, string $command, array $arguments = []): string
    {
        $body = '<rsp:CommandLine xmlns:rsp="' . self::NS_SHELL . '">'
            . '<rsp:Command>' . self::esc($command) . '</rsp:Command>';

        foreach ($arguments as $argument) {
            $body .= '<rsp:Arguments>' . self::esc($argument) . '</rsp:Arguments>';
        }

        $body .= '</rsp:CommandLine>';

        $options = '<w:OptionSet>'
            . '<w:Option Name="WINRS_SKIP_CMD_SHELL">TRUE</w:Option>'
            . '<w:Option Name="WINRS_CONSOLEMODE_STDIN">FALSE</w:Option>'
            . '</w:OptionSet>';

        return $this->wrap(self::A_COMMAND, self::URI_SHELL_CMD, $body, $shellId, $options);
    }

    /** Asks for the next chunk of output. Blocks on the host until output or timeout. */
    public function receive(string $shellId, string $commandId): string
    {
        $body = '<rsp:Receive xmlns:rsp="' . self::NS_SHELL . '" SequenceId="0">'
            . '<rsp:DesiredStream CommandId="' . self::esc($commandId) . '">stdout stderr</rsp:DesiredStream>'
            . '</rsp:Receive>';

        return $this->wrap(self::A_RECEIVE, self::URI_SHELL_CMD, $body, $shellId);
    }

    public function signal(string $shellId, string $commandId, string $signal = self::SIGNAL_TERMINATE): string
    {
        $body = '<rsp:Signal xmlns:rsp="' . self::NS_SHELL . '" CommandId="' . self::esc($commandId) . '">'
            . '<rsp:Code>' . self::esc($signal) . '</rsp:Code>'
            . '</rsp:Signal>';

        return $this->wrap(self::A_SIGNAL, self::URI_SHELL_CMD, $body, $shellId);
    }

    public function deleteShell(string $shellId): string
    {
        return $this->wrap(self::A_DELETE, self::URI_SHELL_CMD, '', $shellId);
    }

    /**
     * An Identify request carries no authentication and no resource. It is the
     * cheapest way to answer "is there a WinRM listener at all" separately from
     * "are these credentials right", which is exactly the distinction the
     * source settings page has to make.
     */
    public function identify(): string
    {
        return '<?xml version="1.0" encoding="UTF-8"?>'
            . '<s:Envelope xmlns:s="' . self::NS_SOAP . '" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">'
            . '<s:Header/><s:Body><wsmid:Identify/></s:Body></s:Envelope>';
    }

    private function wrap(string $action, string $resourceUri, string $body, string $shellId = '', string $options = ''): string
    {
        $selector = $shellId === '' ? '' :
            '<w:SelectorSet><w:Selector Name="ShellId">' . self::esc($shellId) . '</w:Selector></w:SelectorSet>';

        return '<?xml version="1.0" encoding="UTF-8"?>'
            . '<s:Envelope'
            . ' xmlns:s="' . self::NS_SOAP . '"'
            . ' xmlns:a="' . self::NS_ADDR . '"'
            . ' xmlns:w="' . self::NS_WSMAN . '"'
            . ' xmlns:p="' . self::NS_MSWSMAN . '">'
            . '<s:Header>'
            . '<a:To>' . self::esc($this->endpoint) . '</a:To>'
            . '<a:ReplyTo><a:Address s:mustUnderstand="true">'
            . 'http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous'
            . '</a:Address></a:ReplyTo>'
            . '<a:Action s:mustUnderstand="true">' . self::esc($action) . '</a:Action>'
            . '<a:MessageID>uuid:' . self::uuid() . '</a:MessageID>'
            . '<w:ResourceURI s:mustUnderstand="true">' . self::esc($resourceUri) . '</w:ResourceURI>'
            . '<w:MaxEnvelopeSize s:mustUnderstand="true">' . $this->maxEnvelopeSize . '</w:MaxEnvelopeSize>'
            . '<w:OperationTimeout>PT' . $this->operationTimeout . '.000S</w:OperationTimeout>'
            . '<w:Locale xml:lang="' . self::esc($this->locale) . '" s:mustUnderstand="false"/>'
            . '<p:DataLocale xml:lang="' . self::esc($this->locale) . '" s:mustUnderstand="false"/>'
            . $selector
            . $options
            . '</s:Header>'
            . '<s:Body>' . $body . '</s:Body>'
            . '</s:Envelope>';
    }

    /** RFC 4122 version 4, uppercase — the form Windows itself emits. */
    public static function uuid(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);

        return strtoupper(vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4)));
    }

    private static function esc(string $value): string
    {
        return htmlspecialchars($value, ENT_XML1 | ENT_QUOTES, 'UTF-8');
    }
}
