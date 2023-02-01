<?php

use Symfony\Component\DependencyInjection\Argument\RewindableGenerator;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\DependencyInjection\Container;
use Symfony\Component\DependencyInjection\Exception\InvalidArgumentException;
use Symfony\Component\DependencyInjection\Exception\LogicException;
use Symfony\Component\DependencyInjection\Exception\RuntimeException;
use Symfony\Component\DependencyInjection\ParameterBag\FrozenParameterBag;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

/**
 * @internal This class has been auto-generated by the Symfony Dependency Injection Component.
 */
class Symfony_DI_PhpDumper_Test_Uninitialized_Reference extends Container
{
    protected $parameters = [];

    public function __construct()
    {
        $this->services = $this->privates = [];
        $this->methodMap = [
            'bar' => 'getBarService',
            'baz' => 'getBazService',
            'foo1' => 'getFoo1Service',
        ];

        $this->aliases = [];
    }

    public function compile(): void
    {
        throw new LogicException('You cannot compile a dumped container that was already compiled.');
    }

    public function isCompiled(): bool
    {
        return true;
    }

    public function getRemovedIds(): array
    {
        return [
            'foo2' => true,
            'foo3' => true,
        ];
    }

    /**
     * Gets the public 'bar' shared service.
     *
     * @return \stdClass
     */
    protected function getBarService()
    {
        $this->services['bar'] = $instance = new \stdClass();

        $instance->foo1 = ($this->services['foo1'] ?? null);
        $instance->foo2 = null;
        $instance->foo3 = ($this->privates['foo3'] ?? null);
        $instance->closures = [0 => #[\Closure(name: 'foo1', class: 'stdClass')] function () {
            return ($this->services['foo1'] ?? null);
        }, 1 => #[\Closure(name: 'foo2')] function () {
            return null;
        }, 2 => #[\Closure(name: 'foo3', class: 'stdClass')] function () {
            return ($this->privates['foo3'] ?? null);
        }];
        $instance->iter = new RewindableGenerator(function () {
            if (isset($this->services['foo1'])) {
                yield 'foo1' => ($this->services['foo1'] ?? null);
            }
            if (false) {
                yield 'foo2' => null;
            }
            if (isset($this->privates['foo3'])) {
                yield 'foo3' => ($this->privates['foo3'] ?? null);
            }
        }, function () {
            return 0 + (int) (isset($this->services['foo1'])) + (int) (false) + (int) (isset($this->privates['foo3']));
        });

        return $instance;
    }

    /**
     * Gets the public 'baz' shared service.
     *
     * @return \stdClass
     */
    protected function getBazService()
    {
        $this->services['baz'] = $instance = new \stdClass();

        $instance->foo3 = ($this->privates['foo3'] ?? ($this->privates['foo3'] = new \stdClass()));

        return $instance;
    }

    /**
     * Gets the public 'foo1' shared service.
     *
     * @return \stdClass
     */
    protected function getFoo1Service()
    {
        return $this->services['foo1'] = new \stdClass();
    }
}
