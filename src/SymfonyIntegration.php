<?php

namespace updg\roadrunner\symfony;

use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\StreamedResponse;
use Symfony\Component\HttpKernel\Kernel;
use updg\roadrunner\easy\HttpIntegrationInterface;

class SymfonyIntegration implements HttpIntegrationInterface
{
    /** @var Kernel */
    private $_kernel;

    /** @var string */
    private $_kernelClass;

    /** @var array Original $_SERVER data */
    private $originalServer = [];

    /** @var array Symfony env */
    private $_env = 'dev';

    /** @var bool Symfony debug */
    private $_debug = true;

    /** @var Request */
    private $_symfonyRequest;

    /** @var Response */
    private $_symfonyResponse;

    /**
     * SymfonyIntegration constructor.
     *
     * @param string          $kernelClass    Application kernel class. App\Kernel by default.
     * @param string|null     $env            Application environment (prod, dev).
     * @param bool|null       $debug          Debug state of Symfony.
     * @param array|bool|null $trustedProxies Trusted proxies for Symfony or false to disable check.
     * @param array|bool|null $trustedHosts   Trusted hosts for Symfony or false to disable check.
     */
    public function __construct(string $kernelClass = '\App\Kernel', $env = null, $debug = null, $trustedProxies = null, $trustedHosts = null)
    {
        $this->_kernelClass = $kernelClass;

        $env = $env ?? $_SERVER['APP_ENV'] ?? $_ENV['APP_ENV'] ?? 'dev';
        $debug = (bool)($debug ?? $_SERVER['APP_DEBUG'] ?? $_ENV['APP_DEBUG'] ?? ('prod' !== $env));

        if ($debug) {
            umask(0000);

            \Symfony\Component\Debug\Debug::enable();
        }

        if ($trustedProxies = $trustedProxies ?? $_SERVER['TRUSTED_PROXIES'] ?? $_ENV['TRUSTED_PROXIES'] ?? false) {
            Request::setTrustedProxies(explode(',', $trustedProxies), Request::HEADER_X_FORWARDED_ALL ^ Request::HEADER_X_FORWARDED_HOST);
        }

        if ($trustedHosts = $trustedHosts ?? $_SERVER['TRUSTED_HOSTS'] ?? $_ENV['TRUSTED_HOSTS'] ?? $trustedHosts ?? false) {
            Request::setTrustedHosts(explode(',', $trustedHosts));
        }
    }

    /**
     * @inheritdoc
     */
    public function init()
    {
        $this->originalServer = $_SERVER;
        $this->_kernel = new $this->_kernelClass($this->_env, $this->_debug);
    }

    /**
     * @inheritdoc
     */
    public function beforeRequest()
    {
    }

    /**
     * @inheritdoc
     */
    public function afterRequest()
    {
        $this->_kernel->terminate($this->_symfonyRequest, $this->_symfonyResponse);

        if (PHP_SESSION_ACTIVE === \session_status()) {
            \session_write_close();

            \session_id('');
            \session_unset();
        }

        if ($this->_symfonyRequest->hasSession()) {
            $this->_symfonyRequest->getSession()->setId('');
        }
    }

    /**
     * @inheritdoc
     */
    public function shutdown()
    {
        $this->_kernel->shutdown();
    }

    /**
     * @inheritdoc
     */
    public function processRequest(array $ctx, $body): array
    {
        $this->_symfonyRequest = $this->buildSymfonyRequest($ctx, $body);
        $this->_symfonyResponse = $this->_kernel->handle($this->_symfonyRequest);

        if (!$this->_symfonyRequest->cookies->has(\session_name())) {
            $cookie_options = $this->_kernel->getContainer()->getParameter('session.storage.options');
            $this->_symfonyResponse->headers->setCookie(new Cookie(
                \session_name(),
                \session_id(),
                $cookie_options['cookie_lifetime'] ?? 0,
                $cookie_options['cookie_path'] ?? '/',
                $cookie_options['cookie_domain'] ?? '',
                ($cookie_options['cookie_secure'] ?? 'auto') === 'auto' ? $this->_symfonyRequest->isSecure() : (bool)($cookie_options['cookie_secure'] ?? 'auto'),
                $cookie_options['cookie_httponly'] ?? true,
                false,
                $cookie_options['cookie_samesite'] ?? null
            ));
        }

        return $this->buildResponse($this->_symfonyResponse);
    }

    /**
     * Building Symfony request based of RR request data.
     *
     * @param array       $ctx  RR request context.
     * @param string|null $body Body of RR request.
     *
     * @return Request Symfony request.
     */
    private function buildSymfonyRequest(array $ctx, $body): Request
    {
        $_SERVER = $this->configureServer($ctx);

        parse_str($ctx['rawQuery'], $query);

        $requestData = [];
        if (0 === strpos($_SERVER['CONTENT_TYPE'] ?? '', 'application/x-www-form-urlencoded')) {
            parse_str($body, $data);
            $requestData = $data;
        }

        $request = new Request(
            $query,
            $ctx['parsed'] ? json_decode($body, true) : $requestData,
            $ctx['attributes'],
            $ctx['cookies'],
            $ctx['uploads'] ? $this->prepareFiles($ctx['uploads']) : [],
            $_SERVER,
            $body
        );

        return $request;
    }

    /**
     * Building RR response request based of Symfony response.
     *
     * @param Response $response Symfony response
     *
     * @return array Response array for HttpClient
     */
    private function buildResponse(Response $response): array
    {
        $body = '';
        if ($response instanceof BinaryFileResponse) {
            $body = file_get_contents($response->getFile()->getPathname());
        } else {
            if ($response instanceof StreamedResponse) {
                ob_start(function ($buffer) use (&$body) {
                    $body .= $buffer;

                    return '';
                });

                $response->sendContent();
                ob_end_clean();
            } else {
                $body = $response->getContent();
            }
        }

        $headers = $response->headers->all();
        if (!isset($headers['Set-Cookie']) && !isset($headers['set-cookie'])) {
            $cookies = $response->headers->getCookies();
            if (!empty($cookies)) {
                $headers['Set-Cookie'] = [];
                foreach ($cookies as $cookie) {
                    $headers['Set-Cookie'][] = $cookie->__toString();
                }
            }
        }

        return ['status' => $response->getStatusCode(), 'body' => $body, 'headers' => $headers];
    }

    /**
     * Returns altered copy of _SERVER variable. Sets ip-address,
     * request-time and other values.
     *
     * @param array $ctx
     * @return array
     */
    private function configureServer(array $ctx): array
    {
        $uriParts = parse_url($ctx['uri']);

        if (false === $uriParts) {
            throw new \InvalidArgumentException(
                'The source URI string appears to be malformed'
            );
        }

        $server = $this->originalServer;
        $server['REQUEST_TIME'] = time();
        $server['REQUEST_TIME_FLOAT'] = microtime(true);
        $server['REMOTE_ADDR'] = $ctx['attributes']['ipAddress'] ?? $ctx['remoteAddr'] ?? '127.0.0.1';
        $server['SERVER_PROTOCOL'] = $ctx['protocol'];
        $server['REQUEST_METHOD'] = $ctx['method'];

        $server['SERVER_NAME'] = isset($uriParts['host']) ? strtolower($uriParts['host']) : '';
        $server['SERVER_PORT'] = isset($uriParts['port']) ? $uriParts['port'] : null;
        $server['REQUEST_URI'] = isset($uriParts['path']) ? $this->filterPath($uriParts['path']) : '';
        $server['QUERY_STRING'] = isset($uriParts['query']) ? $this->filterQuery($uriParts['query']) : '';

        $server['HTTP_USER_AGENT'] = '';
        $server['HTTP_HOST'] = $server['SERVER_NAME'] . ':' . $server['SERVER_PORT'];
        foreach ($ctx['headers'] as $key => $value) {
            $key = strtoupper(str_replace('-', '_', $key));
            if (\in_array($key, ['CONTENT_TYPE', 'CONTENT_LENGTH'])) {
                $server[$key] = implode(', ', $value);
            } else {
                $server['HTTP_' . $key] = implode(', ', $value);
            }
        }

        return $server;
    }

    /**
     * Converts RR request files array to $_FILES array style.
     *
     * @param array $uploads Array of files from RR request
     * @return array $_FILES style array
     */
    private function prepareFiles(array $uploads)
    {
        foreach ($uploads as $key => &$file) {
            $file['tmp_name'] = $file['tmpName'];
            $file['type'] = $file['mime'];
            unset($file['tmpName'], $file['mime']);
        }

        return $uploads;
    }

    /**
     * Filters the path of a URI to ensure it is properly encoded.
     *
     * @param string $path
     * @return string
     */
    private function filterPath($path)
    {
        $path = preg_replace_callback(
            '/(?:[^a-zA-Z0-9_\-\.~\pL)(:@&=\+\$,\/;%]+|%(?![A - Fa - f0 - 9]{2}))/u',
            [$this, 'urlEncodeChar'],
            $path
        );

        if ('' === $path) {
            // No path
            return $path;
        }

        if ($path[0] !== '/') {
            // Relative path
            return $path;
        }

        // Ensure only one leading slash, to prevent XSS attempts.
        return '/' . ltrim($path, '/');
    }

    /**
     * Filter a query string to ensure it is propertly encoded.
     *
     * Ensures that the values in the query string are properly urlencoded.
     *
     * @param string $query
     * @return string
     */
    private function filterQuery($query)
    {
        if ('' !== $query && strpos($query, '?') === 0) {
            $query = substr($query, 1);
        }

        $parts = explode('&', $query);
        foreach ($parts as $index => $part) {
            list($key, $value) = $this->splitQueryValue($part);
            if ($value === null) {
                $parts[$index] = $this->filterQueryOrFragment($key);
                continue;
            }
            $parts[$index] = sprintf(
                '%s=%s',
                $this->filterQueryOrFragment($key),
                $this->filterQueryOrFragment($value)
            );
        }

        return implode('&', $parts);
    }

    /**
     * Split a query value into a key/value tuple.
     *
     * @param string $value
     * @return array A value with exactly two elements, key and value
     */
    private function splitQueryValue($value)
    {
        $data = explode(' = ', $value, 2);
        if (!isset($data[1])) {
            $data[] = null;
        }
        return $data;
    }

    /**
     * Filter a query string key or value, or a fragment.
     *
     * @param string $value
     * @return string
     */
    private function filterQueryOrFragment($value)
    {
        return preg_replace_callback(
            ' / (?:[^a-zA-Z0-9_\-\.~\pL!\$ & \'\(\)\*\+,;=%:@\/\?]+|%(?![A-Fa-f0-9]{2}))/u',
            [$this, 'urlEncodeChar'],
            $value
        );
    }

    /**
     * URL encode a character returned by a regex.
     *
     * @param array $matches
     * @return string
     */
    private function urlEncodeChar(array $matches)
    {
        return rawurlencode($matches[0]);
    }
}
