<?php

declare(strict_types=1);

namespace LogWarden\Web;

use RuntimeException;
use Throwable;

/**
 * Template rendering. Plain PHP templates, output-escaped by default.
 */
final class View
{
    /** @var array<string, mixed> */
    private array $shared = [];

    public function __construct(private readonly string $templateDir)
    {
    }

    public function share(string $key, mixed $value): void
    {
        $this->shared[$key] = $value;
    }

    /** @param array<string, mixed> $data */
    public function render(string $template, array $data = []): string
    {
        $path = $this->templateDir . '/' . $template . '.php';

        if (!is_file($path)) {
            throw new RuntimeException("Template '{$template}' not found.");
        }

        // $data first: PHP's array union keeps the LEFT operand on a key
        // collision, so the per-render values have to be on the left or the
        // shared defaults would silently win.
        $scope = $data + $this->shared;
        $view  = $this;

        ob_start();

        try {
            (static function () use ($path, $scope, $view): void {
                extract($scope, EXTR_SKIP);
                require $path;
            })();
        } catch (Throwable $e) {
            ob_end_clean();
            throw $e;
        }

        return (string) ob_get_clean();
    }

    /** @param array<string, mixed> $data */
    public function page(string $template, array $data = []): string
    {
        return $this->render('layout', $data + ['content' => $this->render($template, $data)]);
    }

    /** HTML-escape. Every value interpolated into a template goes through this. */
    public static function e(mixed $value): string
    {
        return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    public static function number(int|float $value): string
    {
        return number_format((float) $value, 0, ',', '.');
    }
}
