# RoadRunner <-> Symfony Bridge

Simple bridge between Symfony and RoadRunner without PSR7 layer (HttpClient).

## Installation

### Require this library using composer

`composer req updg/roadrunner-symfony`

### Create psr-worker.php file and add this content to it

```php
<?php
require __DIR__.'/vendor/autoload.php';

if (!isset($_SERVER['APP_ENV'], $_ENV['APP_ENV'])) {
    if (!class_exists(\Symfony\Component\Dotenv\Dotenv::class)) {
        throw new \RuntimeException(
            'APP_ENV environment variable is not defined. You need to define environment variables for configuration or add "symfony/dotenv" as a Composer dependency to load variables from a .env file.'
        );
    }
    (new \Symfony\Component\Dotenv\Dotenv(false))->load(__DIR__ . '/.env');
}


$integration = new \updg\roadrunner\symfony\SymfonyIntegration(App\Kernel::class);
$bridge = new \updg\roadrunner\easy\RoadRunner($integration);
$bridge->run();
```

That's it! Now just run RoadRunner server.
