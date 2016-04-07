<?php
namespace CUMSA\Raven;

class RavenUser {
    protected $crsid;

    function __construct($crsid) {
        $this->crsid = $crsid;
        // TODO: add more details like expiry, etc.
    }

    /**
     * Use the magic method to get to properties on the user object.
     *
     * @param  string $field
     * @return mixed
     */
    public function __get($field)
    {
        if (isset($this->$field))
        {
            return $this->$field;
        }
    }
}