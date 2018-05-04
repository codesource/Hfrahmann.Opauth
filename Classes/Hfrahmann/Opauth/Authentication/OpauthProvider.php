<?php
namespace Hfrahmann\Opauth\Authentication;

/*                                                                        *
 * This script belongs to the Neos Flow package "Hfrahmann.Opauth".          *
 *                                                                        *
 *                                                                        */

use Hfrahmann\Opauth\Exception;
use Hfrahmann\Opauth\Opauth\Configuration;
use Hfrahmann\Opauth\Opauth\Opauth;
use Hfrahmann\Opauth\Service\OpauthAccountService;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\AccountFactory;
use Neos\Flow\Security\AccountRepository;
use Neos\Flow\Security\Authentication\Provider\AbstractProvider;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;

/**
 * Class OpauthProvider
 * @package Hfrahmann\Opauth
 */
class OpauthProvider extends AbstractProvider {

    /**
     * @var AccountFactory
     * @Flow\Inject
     */
    protected $accountFactory;

    /**
     * @var AccountRepository
     * @Flow\Inject
     */
    protected $accountRepository;

    /**
     * @var Opauth
     * @Flow\Inject
     */
    protected $opauth;

    /**
     * @var Configuration
     * @Flow\Inject
     */
    protected $configuration;

    /**
     * @var OpauthAccountService
     * @Flow\Inject
     */
    protected $accountService;

    /**
     * Returns the classnames of the tokens this provider is responsible for.
     *
     * @return array The classname of the token this provider is responsible for
     */
    public function getTokenClassNames() {
        return array(OpauthToken::class);
    }

    /**
     * Tries to authenticate the given token. Sets isAuthenticated to TRUE if authentication succeeded.
     *
     * @param TokenInterface $authenticationToken The token to be authenticated
     * @return void
     *
     * @throws UnsupportedAuthenticationTokenException
     * @throws Exception
     */
    public function authenticate(TokenInterface $authenticationToken) {
        if (!($authenticationToken instanceof OpauthToken)) {
            throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1381598908);
        }

        $response = $this->opauth->getResponse();

        if($response !== NULL && $response->isAuthenticationSucceeded()) {
            $accountIdentifier = $this->accountService->createAccountIdentifier($response);
            $authenticationProviderName = $this->name;

            $account = $this->accountRepository->findByAccountIdentifierAndAuthenticationProviderName($accountIdentifier, $authenticationProviderName);

            if($account !== NULL) {
                $authenticationToken->setAccount($account);
                $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
            }
        } else {
            $authenticationToken->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
        }
    }

}

?>