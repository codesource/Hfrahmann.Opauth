<?php
namespace Hfrahmann\Opauth\ViewHelpers;

/*                                                                        *
 * This script belongs to the Neos Flow package "Hfrahmann.Opauth".          *
 *                                                                        *
 *                                                                        */

use Hfrahmann\Opauth\Opauth\Configuration;
use Neos\FluidAdaptor\Core\ViewHelper\AbstractViewHelper;
use Neos\Flow\Annotations as Flow;

/**
 * A view helper for creating URIs for OPAuth-Actions
 *
 * = Examples =
 *
 * <code title="Defaults">
 * {namespace opauth=Hfrahmann\Opauth\ViewHelpers}
 *
 * {opauth:opauthStrategyUri(strategy:'facebook')}
 * </code>
 * <output>
 * /opauth/facebook
 * </output>
 */
class OpauthStrategyUriViewHelper extends AbstractViewHelper {

    /**
     * @Flow\Inject
     * @var Configuration
     */
    protected Configuration $opauthConfiguration;

    /**
     * @param string $strategy
     *
     * @return string
     */
    public function render(string $strategy = ''): string
    {
        $opauthSettings = $this->opauthConfiguration->getConfiguration();

        return $opauthSettings['path'] . $strategy;
    }

}
