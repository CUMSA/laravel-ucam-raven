<?php
namespace CUMSA\Raven\Http\Controllers;

use App\Http\Controllers\Controller;
use App\User;
use CUMSA\Raven\RavenAuth;
use CUMSA\Raven\RavenUser;
use Auth;

class RavenController extends Controller {
    protected $raven;

    private $redirectTo = '/home';

    public function __construct(RavenAuth $raven) {
        $this->raven = $raven;
    }

    /**
     * Redirect the user to the Raven authentication page.
     *
     * @return Response
     */
    public function redirectToProvider() {
        return $this->raven->redirect();
    }

    /**
     * Obtain the user information from Raven.
     *
     * @return Response
     */
    public function handleProviderCallback() {
        $user = $this->raven->user();
        if (is_null($user)) {
            return redirect('/')->with('message', 'Login cancelled');
        }

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

        $user = User::create([
            'name' => $ravenUser->crsid,
            'email' => $ravenUser->crsid . '@cam.ac.uk', // TODO: get actual stuff from lookup
        ]);
        $user->crsid = $ravenUser->crsid;
        return $user;
    }
}
