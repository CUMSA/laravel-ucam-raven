<?php
namespace CUMSA\Raven;

use CUMSA\Raven\RavenAuth;
use Illuminate\Support\ServiceProvider;

class RavenServiceProvider extends ServiceProvider {
    /**
     * Bootstrap the application events.
     *
     * @return void
     */
    function boot() {
        include __DIR__ . '/../../routes.php';
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register() {
        $this->app->singleton('CUMSA\Raven\RavenAuth', function ($app) {
            return new RavenAuth(new UCamWebauth([
                'do_session' => false,
                'hostname' => $_SERVER['HTTP_HOST'],
            ]));
        });
    }
    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides() {
        return array();
    }
}
