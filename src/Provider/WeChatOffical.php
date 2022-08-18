<?php

namespace NomisCZ\OAuth2\Client\Provider;

use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\ArrayAccessorTrait;
use NomisCZ\OAuth2\Client\Provider\Exception\WeChatIdentityProviderException;
use Psr\Http\Message\ResponseInterface;


class WeChatOffical extends AbstractProvider
{
    use ArrayAccessorTrait;

    protected $appid;
    protected $secret;
    protected $redirect_uri;

    const BASE_AUTH_URL = 'https://open.weixin.qq.com/connect/oauth2';

    const BASE_ACCESS_TOKEN_URL = 'https://api.weixin.qq.com';

    public function getBaseAuthorizationUrl()
    {
        return self::BASE_AUTH_URL.'/authorize';
    }

    protected function getAuthorizationParameters(array $options)
    {
        $options += [
            'appid' => $this->appid
        ];

        if (!isset($options['redirect_uri'])) {
            $options['redirect_uri'] = $this->redirect_uri;
        }

        $options += [
            'response_type' => 'code'
        ];

        if (empty($options['scope'])) {
            $options['scope'] = 'snsapi_userinfo';
        }

        if (empty($options['state'])) {
            $options['state'] = $this->getRandomState();
        }

        $this->state = $options['state'];

        return $options;

    }

    public function getBaseAccessTokenUrl(array $params)
    {
        return self::BASE_ACCESS_TOKEN_URL.'/sns/oauth2/access_token';
    }

    public function getAccessToken($grant, array $options = [])
    {
        $grant = $this->verifyGrant($grant);
        $params = [
            'appid'  => $this->appid,
            'secret' => $this->secret
        ];

        $params   = $grant->prepareRequestParameters($params, $options);
        $request  = $this->getAccessTokenRequest($params);
        $response = $this->getParsedResponse($request);
        $prepared = $this->prepareAccessTokenResponse($response);

        return $this->createAccessToken($prepared, $grant);
    }

    protected function createAccessToken(array $response, AbstractGrant $grant)
    {
        return new AccessToken($response);
    }

    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        $access_token = $token->getToken();
        $openid = $token->getValues()['openid'];

        return sprintf("%s/sns/userinfo?access_token=%s&openid=%s", self::BASE_ACCESS_TOKEN_URL, $access_token, $openid);
    }

    protected function getDefaultScopes()
    {
        return ['snsapi_userinfo'];
    }

    protected function checkResponse(ResponseInterface $response, $data)
    {
        if ($response->getStatusCode() >= 400) {
            throw WeChatIdentityProviderException::clientException($response, $data);
        }
    }

    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new WeChatResourceOwner($response);
    }
    
}