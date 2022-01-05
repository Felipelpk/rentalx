import { NextFunction, Request, Response } from "express";
import { verify } from "jsonwebtoken";
import { AppError } from "../errors/AppError";
import { UsersRepository } from "../modules/accounts/repositories/implementations/UsersRepository";

interface IPayload {
    sub: string;
}

export async function ensureAuthenticated(request: Request, response: Response, next: NextFunction){
    // Bearer token
    const authHeader = request.headers.authorization;

    // Bearer token is null ? 
    if(!authHeader){
        throw new AppError("Token is missing", 401);
    }

    //Bearer Token brake information
    const [, token] = authHeader.split(" ");

    // Token validation
    try{
        const { sub: user_id } = verify(token, "a48fc16d6aff1c1c88845fe7de4d1666") as IPayload;
        const usersRepository = new UsersRepository();
        const user = usersRepository.findById(user_id);
        
        if(!user){
            throw new AppError("User does not exists!", 401);
        }

        request.user = {
            id: user_id
        }
        
        next();
    }catch{
        throw new AppError("Invalid Token", 401);
    }

}