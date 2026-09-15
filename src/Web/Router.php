<?php

declare(strict_types=1);

namespace LogWarden\Web;

/**
 * Exact-match router. Deliberately minimal — LogWarden has a handful of pages
 * and no public API, so pattern matching would be machinery without a job.
 */
final class Router
{
    /** @var array<string, array<string, callable>> */
    private array $routes = ['GET' => [], 'POST' => []];

    public function get(string $path, callable $handler): void
    {
        $this->routes['GET'][$path] = $handler;
    }

    public function post(string $path, callable $handler): void
    {
        $this->routes['POST'][$path] = $handler;
    }

    public function dispatch(string $method, string $uri): Response
    {
        $path = parse_url($uri, PHP_URL_PATH) ?: '/';
        $path = '/' . trim((string) $path, '/');
        $path = $path === '/' ? '/' : rtrim($path, '/');

        // HEAD is handled as GET; the response layer drops the body.
        $method = $method === 'HEAD' ? 'GET' : $method;

        $handler = $this->routes[$method][$path] ?? null;

        if ($handler === null) {
            $allowed = array_keys(array_filter(
                $this->routes,
                static fn (array $routes): bool => isset($routes[$path]),
            ));

            return $allowed === []
                ? Response::notFound()
                : Response::methodNotAllowed($allowed);
        }

        return $handler();
    }
}
