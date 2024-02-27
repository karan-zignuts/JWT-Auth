<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Auth;
use Validator;
use Illuminate\Support\Facades\Hash;

class UserController extends Controller
{
    public function register(Request $request){

        $validator = Validator::make($request->all(),[

            'name' => 'required',
            'email'=>'required|unique:users,email',
            'password'=>'required|min:6|max:12|string'
        ]);

        if($validator ->fails()) {
            return response()->json(['errors'=>$validator->errors()],401); 
        }
        
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password)
        ]);

        return response()->json([
            'message' => 'User Register successfully',
            'user' => $user
        ]);
    }

    public  function login(Request $request){

        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string',
        ]);
    
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 401);
        }
    
        $user = User::where('email', $request->email)->first();
    
        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    
        $token = auth()->attempt($validator->validated());
    
        if (!$token) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    
        return $this->respondWithToken($token);
    }
    protected function respondWithToken($token){
        return response() -> json([
            'message' => 'user login successfully',
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL()*60
        ]);
    }

    public function profile(){
        return response()->json(auth()->user());
    }
}
