<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Bundle\SecurityBundle\Security;

use Psr\Container\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\LogicException;
use Symfony\Component\Security\Core\Security as LegacySecurity;
use Symfony\Component\Security\Http\Event\LogoutEvent;

/**
 * Helper class for commonly-needed security tasks.
 *
 * @final
 */
class Security extends LegacySecurity
{
    public function __construct(private ContainerInterface $container)
    {
        parent::__construct($container, false);
    }

    public function getFirewallConfig(Request $request): ?FirewallConfig
    {
        return $this->container->get('security.firewall.map')->getFirewallConfig($request);
    }

    /**
     * Logout the current user by dispatching the LogoutEvent.
     *
     * @return Response|null The LogoutEvent's Response if any
     */
    public function logout(): ?Response
    {
        $request = $this->container->get('request_stack')->getMainRequest();

        if (!class_exists(LogoutEvent::class)) {
            throw new \LogicException('Security HTTP is missing. Try running "composer require symfony/security-http".');
        }
        $logoutEvent = new LogoutEvent($request, $this->container->get('security.token_storage')->getToken());
        $firewallConfig = $this->container->get('security.firewall.map')->getFirewallConfig($request);

        if (!$firewallConfig) {
            throw new LogicException('It is not possible to logout, as the request is not behind a firewall.');
        }
        $firewallName = $firewallConfig->getName();

        $this->container->get('security.firewall.event_dispatcher_locator')->get($firewallName)->dispatch($logoutEvent);
        $this->container->get('security.token_storage')->setToken();

        return $logoutEvent->getResponse();
    }
}
