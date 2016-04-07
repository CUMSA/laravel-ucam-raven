<?php
namespace CUMSA\Raven;

use CUMSA\Raven\RavenUser;
use Exception;

class RavenAuth {
    protected $webauth;

    public function __construct(UCamWebauth $webauth) {
        $this->webauth = $webauth;
    }

    public function redirect() {
        return $this->webauth->redirect();
    }

    public function user() {
        $ret = $this->webauth->callback();
        if (!$ret || !$this->webauth->success()) {
            if (!in_array($this->webauth->status(), ['410'])) {
                throw new Exception('UCamWebAuth: ' . $this->webauth->status() . $this->webauth->msg());
            }
        } else {
            return new RavenUser($this->webauth->principal());
        }
        return null;
    }
}