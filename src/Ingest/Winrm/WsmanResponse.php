<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Winrm;

use DOMDocument;
use DOMXPath;

/**
 * Parses a WS-Management response envelope.
 *
 * Every accessor works through XPath with registered prefixes rather than
 * through element names: Windows is free to choose its own prefixes and does
 * change them between the shell and the enumeration services, so matching on
 * `rsp:Stream` as text would work until the day it does not.
 */
final class WsmanResponse
{
    private readonly DOMXPath $xpath;

    private function __construct(private readonly DOMDocument $dom)
    {
        $this->xpath = new DOMXPath($dom);
        $this->xpath->registerNamespace('s', WsmanEnvelope::NS_SOAP);
        $this->xpath->registerNamespace('a', WsmanEnvelope::NS_ADDR);
        $this->xpath->registerNamespace('w', WsmanEnvelope::NS_WSMAN);
        $this->xpath->registerNamespace('rsp', WsmanEnvelope::NS_SHELL);
        $this->xpath->registerNamespace('f', WsmanEnvelope::NS_FAULT);
    }

    /**
     * @throws WinrmException  when the payload is not parseable XML
     * @throws WsmanFault      when the payload is a SOAP fault
     */
    public static function parse(string $xml): self
    {
        $dom = new DOMDocument();

        // No LIBXML_NOENT, so entities are never substituted, and LIBXML_NONET
        // so nothing is fetched. A WinRM endpoint is a host we already trust,
        // but "trusted" and "may hand this process arbitrary local files" are
        // not the same statement — and a compromised DC is exactly the
        // scenario this software exists for.
        $previous = libxml_use_internal_errors(true);
        $ok = $dom->loadXML($xml, LIBXML_NONET);
        $errors = libxml_get_errors();
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        if ($ok === false) {
            $first = $errors[0]->message ?? 'unbekannter Parserfehler';
            throw new WinrmException('Antwort ist kein gültiges XML: ' . trim($first));
        }

        $response = new self($dom);
        $response->throwOnFault();

        return $response;
    }

    private function throwOnFault(): void
    {
        $fault = $this->xpath->query('//s:Fault')->item(0);
        if ($fault === null) {
            return;
        }

        $reason  = $this->text('//s:Fault/s:Reason/s:Text') ?? 'WS-Management-Fehler';
        $subcode = $this->text('//s:Fault/s:Code/s:Subcode/s:Value');
        $detail  = $this->text('//s:Fault/s:Detail//f:Message');
        $codeRaw = $this->attr('//f:WSManFault', 'Code');

        // The provider fault is where Windows puts the actual reason when the
        // command itself failed rather than the transport.
        $provider = $this->text('//s:Fault/s:Detail//f:ProviderFault');

        // "wsman:TimedOut" -> "TimedOut": the local part is the stable half,
        // the prefix is whatever the responding host happened to pick.
        if ($subcode !== null && str_contains($subcode, ':')) {
            $subcode = substr($subcode, strrpos($subcode, ':') + 1);
        }

        throw new WsmanFault(
            trim($reason),
            $codeRaw === null ? null : (int) $codeRaw,
            $subcode,
            $detail === null ? null : trim($detail),
            $provider === null ? null : trim($provider),
        );
    }

    public function shellId(): ?string
    {
        return $this->text('//rsp:Shell/rsp:ShellId')
            ?? $this->text('//w:Selector[@Name="ShellId"]');
    }

    public function commandId(): ?string
    {
        return $this->text('//rsp:CommandResponse/rsp:CommandId');
    }

    /**
     * Decoded output of one stream.
     *
     * Windows splits output across several base64 `Stream` elements per
     * response and may split a multi-byte character across that boundary, so
     * the chunks are concatenated before anything looks at them as text.
     */
    public function stream(string $name): string
    {
        $out = '';

        foreach ($this->xpath->query('//rsp:Stream[@Name="' . $name . '"]') as $node) {
            $chunk = base64_decode($node->textContent, true);
            if ($chunk !== false) {
                $out .= $chunk;
            }
        }

        return $out;
    }

    /** True once the command has finished; the exit code is only valid then. */
    public function isDone(): bool
    {
        $state = $this->attr('//rsp:CommandState', 'State');

        return $state !== null && str_ends_with($state, '/Done');
    }

    public function exitCode(): ?int
    {
        $code = $this->text('//rsp:CommandState/rsp:ExitCode');

        return $code === null ? null : (int) $code;
    }

    public function productVendor(): ?string
    {
        $x = new DOMXPath($this->dom);
        $x->registerNamespace('wsmid', 'http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd');

        return $x->query('//wsmid:ProductVendor')->item(0)?->textContent;
    }

    public function protocolVersion(): ?string
    {
        $x = new DOMXPath($this->dom);
        $x->registerNamespace('wsmid', 'http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd');

        return $x->query('//wsmid:ProtocolVersion')->item(0)?->textContent;
    }

    private function text(string $query): ?string
    {
        return $this->xpath->query($query)->item(0)?->textContent;
    }

    private function attr(string $query, string $name): ?string
    {
        $node = $this->xpath->query($query)->item(0);
        if (!$node instanceof \DOMElement) {
            return null;
        }

        return $node->hasAttribute($name) ? $node->getAttribute($name) : null;
    }
}
