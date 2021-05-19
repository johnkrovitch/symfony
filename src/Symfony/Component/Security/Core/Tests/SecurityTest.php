<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Security\Core\Tests;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Symfony\Bundle\SecurityBundle\Security\FirewallConfig;
use Symfony\Bundle\SecurityBundle\Security\FirewallMap;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Exception\LogicException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Http\Event\LogoutEvent;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * @group legacy
 */
class SecurityTest extends TestCase
{
    public function testGetToken()
    {
        $token = new UsernamePasswordToken(new InMemoryUser('foo', 'bar'), 'provider');
        $tokenStorage = $this->createMock(TokenStorageInterface::class);

        $tokenStorage->expects($this->once())
            ->method('getToken')
            ->willReturn($token);

        $container = $this->createContainer('security.token_storage', $tokenStorage);

        $security = new Security($container);
        $this->assertSame($token, $security->getToken());
    }

    /**
     * @dataProvider getUserTests
     */
    public function testGetUser($userInToken, $expectedUser)
    {
        $token = $this->createMock(TokenInterface::class);
        $token->expects($this->any())
            ->method('getUser')
            ->willReturn($userInToken);
        $tokenStorage = $this->createMock(TokenStorageInterface::class);

        $tokenStorage->expects($this->once())
            ->method('getToken')
            ->willReturn($token);

        $container = $this->createContainer('security.token_storage', $tokenStorage);

        $security = new Security($container);
        $this->assertSame($expectedUser, $security->getUser());
    }

    public function getUserTests()
    {
        yield [null, null];

        $user = new InMemoryUser('nice_user', 'foo');
        yield [$user, $user];
    }

    public function testIsGranted()
    {
        $authorizationChecker = $this->createMock(AuthorizationCheckerInterface::class);

        $authorizationChecker->expects($this->once())
            ->method('isGranted')
            ->with('SOME_ATTRIBUTE', 'SOME_SUBJECT')
            ->willReturn(true);

        $container = $this->createContainer('security.authorization_checker', $authorizationChecker);

        $security = new Security($container);
        $this->assertTrue($security->isGranted('SOME_ATTRIBUTE', 'SOME_SUBJECT'));
    }

    public function testLogout()
    {
        $request = new Request();
        $requestStack = $this->createMock(RequestStack::class);
        $requestStack
            ->expects($this->once())
            ->method('getMainRequest')
            ->willReturn($request)
        ;

        $token = $this->createMock(TokenInterface::class);
        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage
            ->expects($this->once())
            ->method('getToken')
            ->willReturn($token)
        ;
        $tokenStorage
            ->expects($this->once())
            ->method('setToken')
        ;

        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $eventDispatcher
            ->expects($this->once())
            ->method('dispatch')
            ->with(new LogoutEvent($request, $token))
        ;

        $firewallMap = $this->createMock(FirewallMap::class);
        $firewallConfig = new FirewallConfig('my_firewall', 'user_checker');
        $firewallMap
            ->expects($this->once())
            ->method('getFirewallConfig')
            ->willReturn($firewallConfig)
        ;

        $eventDispatcherLocator = $this->createMock(ContainerInterface::class);
        $eventDispatcherLocator
            ->expects($this->atLeastOnce())
            ->method('get')
            ->willReturnMap([
                ['my_firewall', $eventDispatcher],
            ])
        ;

        $container = $this->createMock(ContainerInterface::class);
        $container
            ->expects($this->atLeastOnce())
            ->method('get')
            ->willReturnMap([
                ['request_stack', $requestStack],
                ['security.token_storage', $tokenStorage],
                ['security.firewall.map', $firewallMap],
                ['security.firewall.event_dispatcher_locator', $eventDispatcherLocator],
            ])
        ;
        $security = new Security($container);
        $security->logout();
    }

    public function testLogoutWithoutFirewall()
    {
        $request = new Request();
        $requestStack = $this->createMock(RequestStack::class);
        $requestStack
            ->expects($this->once())
            ->method('getMainRequest')
            ->willReturn($request)
        ;

        $token = $this->createMock(TokenInterface::class);
        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage
            ->expects($this->once())
            ->method('getToken')
            ->willReturn($token)
        ;

        $firewallMap = $this->createMock(FirewallMap::class);
        $firewallMap
            ->expects($this->once())
            ->method('getFirewallConfig')
            ->willReturn(null)
        ;

        $container = $this->createMock(ContainerInterface::class);
        $container
            ->expects($this->atLeastOnce())
            ->method('get')
            ->willReturnMap([
                ['request_stack', $requestStack],
                ['security.token_storage', $tokenStorage],
                ['security.firewall.map', $firewallMap],
            ])
        ;

        $this->expectException(LogicException::class);
        $security = new Security($container);
        $security->logout();
    }

    private function createContainer($serviceId, $serviceObject): MockObject
    {
        $container = $this->createMock(ContainerInterface::class);

        $container->expects($this->atLeastOnce())
            ->method('get')
            ->with($serviceId)
            ->willReturn($serviceObject);

        return $container;
    }
}
