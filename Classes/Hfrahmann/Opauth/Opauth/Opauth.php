<?php

namespace Hfrahmann\Opauth\Opauth;

/*                                                                        *
 * This script belongs to the Neos Flow package "Hfrahmann.Opauth".          *
 *                                                                        *
 *                                                                        */

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Mvc\Exception\NoSuchArgumentException;
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
     * @var ActionRequest
     */
    protected ActionRequest $actionRequest;

    /**
     * @var Response|null
     */
    protected ?Response $response;

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
     *
     * @throws NoSuchArgumentException
     */
    public function getResponse(): ?Response
    {
        if ($this->actionRequest->hasArgument('opauth')) {
            $data = $this->actionRequest->getArgument('opauth');
            $response = unserialize(base64_decode($data));
            if (!is_array($response)) {
                $response = json_decode($data, true);
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
