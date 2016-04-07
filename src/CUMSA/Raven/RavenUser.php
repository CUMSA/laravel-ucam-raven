<?php
namespace CUMSA\Raven;

class RavenUser {
    protected $crsid;

    function __construct($crsid) {
        $this->crsid = $crsid;
        // TODO: add more details like expiry, etc.
    }
}