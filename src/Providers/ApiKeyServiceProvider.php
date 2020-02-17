<?php

namespace Victorybiz\LaravelApiKey\Providers;

use Victorybiz\LaravelApiKey\Console\Commands\ActivateApiKey;
use Victorybiz\LaravelApiKey\Console\Commands\DeactivateApiKey;
use Victorybiz\LaravelApiKey\Console\Commands\DeleteApiKey;
use Victorybiz\LaravelApiKey\Console\Commands\GenerateApiKey;
use Victorybiz\LaravelApiKey\Console\Commands\ListApiKeys;
use Victorybiz\LaravelApiKey\Http\Middleware\AuthorizeApiKey;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;

class ApiKeyServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application services.
     *
     * @param Router $router
     * @return void
     */
    public function boot(Router $router)
    {
        $this->registerMiddleware($router);
        $this->registerMigrations(__DIR__ . '/../../database/migrations');
    }

    /**
     * Register the application services.
     *
     * @return void
     */
    public function register() {
        $this->commands([
            ActivateApiKey::class,
            DeactivateApiKey::class,
            DeleteApiKey::class,
            GenerateApiKey::class,
            ListApiKeys::class,
        ]);
    }

    /**
     * Register middleware
     *
     * Support added for different Laravel versions
     *
     * @param Router $router
     */
    protected function registerMiddleware(Router $router)
    {
        $versionComparison = version_compare(app()->version(), '5.4.0');

        if ($versionComparison >= 0) {
            $router->aliasMiddleware('auth.apikey', AuthorizeApiKey::class);
        } else {
            $router->middleware('auth.apikey', AuthorizeApiKey::class);
        }
    }

    /**
     * Register migrations
     */
    protected function registerMigrations($migrationsDirectory)
    {
        $this->publishes([
            $migrationsDirectory => database_path('migrations')
        ], 'migrations');
    }
}
