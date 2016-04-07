<?php
Route::group([
    'prefix' => 'auth/raven',
    'middleware' => 'web',
], function () {
    Route::get('/', array(
        'as' => 'raven_login',
        'uses' => 'CUMSA\Raven\Http\Controllers\RavenController@redirectToProvider',
    ));
    Route::get('/callback', array(
        'as' => 'raven_callback',
        'uses' => 'CUMSA\Raven\Http\Controllers\RavenController@handleProviderCallback',
    ));
});