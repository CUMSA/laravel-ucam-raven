<?php
namespace CUMSA\Raven;

use CUMSA\Raven\RavenUser;

class RavenAuth {
    public function __construct(UCamWebauth $webauth) {
        $this->webauth = $webauth;
    }

    public function redirect() {
        return $this->webauth->redirect();
    }

    public function user() {
        $ret = $this->webauth->callback();
        } if (!$ret || !$ret->success()) {
            throw new Exception('UCamWebAuth: ' . $ret->status() . $ret->msg());
        } else {
            return new RavenUser($ret->principal());
        }
        return null;
    }
}