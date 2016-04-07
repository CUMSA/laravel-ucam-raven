<?php
namespace CUMSA\Raven\Http\Controllers;

use App\Http\Controllers\Controller;
use App\User;
use CUMSA\Raven\RavenAuth;
use CUMSA\Raven\RavenUser;

class RavenController extends Controller {
    private $redirectTo = '/home';

    /**
     * Redirect the user to the Raven authentication page.
     *
     * @return Response
     */
    public function redirectToProvider() {
        $raven = new RavenAuth;
        return $auth->redirect();
    }

    /**
     * Obtain the user information from Raven.
     *
     * @return Response
     */
    public function handleProviderCallback() {
        $raven = new RavenAuth;
        $user = $raven->user();

        $authUser = $this->findOrCreateUser($user);
        Auth::login($authUser, true);

        return redirect()->intended($this->redirectTo);
    }

    /**
     * Return user if exists; create and return if doesn't
     * Assumes that User model has crsid as an attribute.
     *
     * @param $ravenUser
     * @return User
     */
    private function findOrCreateUser(RavenUser $ravenUser) {
        if ($authUser = User::where('crsid', $ravenUser->crsid)->first()) {
            return $authUser;
        }

        return User::create([
            'name' => $ravenUser->crsid,
            'email' => $ravenUser->crsid . '@cam.ac.uk', // TODO: get actual stuff from lookup
            'crsid' => $ravenUser->crsid,
        ]);
    }
}
