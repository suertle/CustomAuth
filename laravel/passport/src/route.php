<?php

use Illuminate\Http\Request;

/*
|--------------------------------------------------------------------------
| Custom Auth Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::group(['prefix' => 'oauth', 'namespace' => '\CustomAuth\Passport\Http\Controllers'], function () {
	Route::post('/token', ['uses' => 'AccessTokenController@issueToken'])->middleware('throttle');
});
