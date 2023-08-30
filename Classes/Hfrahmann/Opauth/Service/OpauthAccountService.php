<?php

namespace Hfrahmann\Opauth\Service;

/*                                                                        *
 * This script belongs to the Neos Flow package "Hfrahmann.Opauth".       *
 *                                                                        *
 *                                                                        */

use Hfrahmann\Opauth\Exception;
use Hfrahmann\Opauth\Opauth\Configuration;
use Hfrahmann\Opauth\Opauth\Response;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\AccountFactory;
use Neos\Flow\Security\AccountRepository;

/**
 * Class OpauthResponse
 * @Flow\Scope("singleton")
 */
class OpauthAccountService
{

    /**
     * @var AccountFactory
     * @Flow\Inject
     */
    protected AccountFactory $accountFactory;

    /**
     * @var AccountRepository
     * @Flow\Inject
     */
    protected AccountRepository $accountRepository;

    /**
     * @var Configuration
     * @Flow\Inject
     */
    protected Configuration $configuration;

    /**
     * Creates an account identifier with the strategy and the unique userID.
     *
     * @param Response|null $opauthResponse
     *
     * @return string
     *
     * @throws Exception
     */
    public function createAccountIdentifier(?Response $opauthResponse): string
    {
        if ($opauthResponse == NULL)
            throw new Exception("OpauthResponse cannot be NULL.", 1381596920);

        $strategy = $opauthResponse->getStrategy();
        $userID = $opauthResponse->getUserID();

        if (strlen($strategy) > 0 && strlen($userID) > 0) {
            return $strategy . ':' . $userID;
        } else {
            throw new Exception("No Strategy or UserID given.", 1381596915);
        }
    }

    /**
     * Return an OPAuth account.
     * If an account with the given data does not exist a new account will be created.
     *
     * @param Response|null $opauthResponse
     *
     * @return Account
     *
     * @throws Exception
     */
    public function getAccount(?Response $opauthResponse): Account
    {
        if ($opauthResponse == NULL)
            throw new Exception("OpauthResponse cannot be NULL.", 1381596921);

        $accountIdentifier = $this->createAccountIdentifier($opauthResponse);
        $authenticationProviderName = $this->configuration->getAuthenticationProviderName();

        $account = $this->accountRepository->findByAccountIdentifierAndAuthenticationProviderName($accountIdentifier, $authenticationProviderName);

        if ($account === NULL) {
            $roleIdentifier = $this->configuration->getDefaultRoleIdentifier();
            $roleIdentifierArray = array();
            if (is_array($roleIdentifier))
                $roleIdentifierArray = $roleIdentifier;
            if (is_string($roleIdentifier))
                $roleIdentifierArray = array($roleIdentifier);

            $account = $this->accountFactory->createAccountWithPassword($accountIdentifier, NULL, $roleIdentifierArray, $authenticationProviderName);
        }

        return $account;
    }

    /**
     * Checks if the given account is already in the account repository
     *
     * @param Account $account
     * @return bool
     */
    public function doesAccountExist(Account $account)
    {
        $accountIdentifier = $account->getAccountIdentifier();
        $authenticationProviderName = $account->getAuthenticationProviderName();

        $existingAccount = $this->accountRepository->findByAccountIdentifierAndAuthenticationProviderName($accountIdentifier, $authenticationProviderName);

        return ($existingAccount !== NULL);
    }

}
