<?php

namespace Victorybiz\LaravelApiKey\Http\Middleware;

use Closure;
use Victorybiz\LaravelApiKey\Models\ApiKey;
use Victorybiz\LaravelApiKey\Models\ApiKeyAccessEvent;
use Illuminate\Http\Request;

class AuthorizeApiKey
{
    const AUTH_HEADER = 'X-Authorization';

    /**
     * Handle the incoming request
     *
     * @param Request $request
     * @param Closure $next
     * @return \Illuminate\Contracts\Routing\ResponseFactory|mixed|\Symfony\Component\HttpFoundation\Response
     */
    public function handle(Request $request, Closure $next)
    {
        $header = $request->header(self::AUTH_HEADER);
        $apiKey = ApiKey::getByKey($header);

        if ($apiKey instanceof ApiKey) {
            $this->logAccessEvent($request, $apiKey);
            return $next($request);
        }

        return response([
            'status' => false,
	        'message' => 'Unauthorized request, use a valid API Key.',
        ], 401);
    }

    /**
     * Log an API key access event
     *
     * @param Request $request
     * @param ApiKey  $apiKey
     */
    protected function logAccessEvent(Request $request, ApiKey $apiKey)
    {
        $event = new ApiKeyAccessEvent;
        $event->api_key_id = $apiKey->id;
        $event->ip_address = $request->ip();
        $event->url        = $request->fullUrl();
        $event->save();
    }
}
