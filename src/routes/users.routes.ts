import { Router } from "express";
import multer from "multer";
import { CreateUserController } from "../modules/accounts/useCases/createUser/CreateUserController";
import { UpdatedUserAvatarController } from "../modules/accounts/useCases/updateUserAvatar/UpdatedUserAvatarController";
import uploadConfig from "../config/upload";
import { ensureAuthenticated } from "../middlewares/ensureAuthenticated";

const usersRoutes = Router();

const createUserController = new CreateUserController();
const updatedUserAvatarController = new UpdatedUserAvatarController();

const uploadAvatar = multer(uploadConfig.upload("./tmp/avatar"));

usersRoutes.post("/", createUserController.handle);

usersRoutes.patch("/avatar", ensureAuthenticated ,uploadAvatar.single("avatar"),updatedUserAvatarController.handle);

export { usersRoutes }  