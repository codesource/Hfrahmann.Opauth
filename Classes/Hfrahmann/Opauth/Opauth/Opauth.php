<?php

namespace Hfrahmann\Opauth\Opauth;

/*                                                                        *
 * This script belongs to the Neos Flow package "Hfrahmann.Opauth".          *
 *                                                                        *
 *                                                                        */

use GuzzleHttp\Psr7\ServerRequest;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\ActionRequest;
use Opauth as OpauthBase;

/**
 * Class Opauth
 * @Flow\Scope("singleton")
 */
class Opauth
{

    /**
     * @var OpauthBase|null
     */
    protected ?OpauthBase $opauth = null;

    /**
     * @var Configuration
     * @Flow\Inject
     */
    protected Configuration $configuration;

    /**
     * @var ActionRequest|null
     */
    protected ?ActionRequest $actionRequest = null;

    /**
     * @var Response|null
     */
    protected ?Response $response = null;

    /**
     * @param ActionRequest $actionRequest
     */
    public function setActionRequest(ActionRequest $actionRequest): void
    {
        $this->actionRequest = $actionRequest;
    }

    /**
     * Returns the real OPAuth object
     *
     * @return OpauthBase
     */
    public function getOpauth(): OpauthBase
    {
        if ($this->opauth === null) {
            $this->workarounds();
            $configuration = $this->configuration->getConfiguration();
            $this->opauth = new OpauthBase($configuration, FALSE);
        }

        return $this->opauth;
    }

    /**
     * Returns an Response object containing the OPAuth data
     *
     * @return Response|null
     */
    public function getResponse(): ?Response
    {
        $data = ServerRequest::fromGlobals()->getParsedBody();
        if ($data && $data['opauth']) {
            $response = null;
            $parsedData = base64_decode($data['opauth']) ?: $data['opauth'];
            try{
                $response = unserialize($parsedData, ['allowed_classes' => false]);
            }catch(\Exception){
            }
            if (!is_array($response)) {
                $response = json_decode($parsedData, true);
            }
            if (!is_array($response)) {
                $response = [];
            }
            $this->response = new Response($response);
        }

        return $this->response;
    }

    /**
     * Some Workarounds for some strategies.
     *
     * @return void
     */
    protected function workarounds(): void
    {
        // When canceling a Twitter-Authentication, Flow returns a notice.
        if (!isset($_REQUEST['oauth_token']))
            $_REQUEST['oauth_token'] = '';
    }

}
