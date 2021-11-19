import { Router } from "express";
import { v4 as uuidV4 } from "uuid";
import { Category } from "../model/Category";
import { CategoriesRepository } from "../repositories/CategoriesRepository";
import { CreateCategoryService } from "../serivces/CreateCategoryService";

const categoriesRoutes = Router();
const categoriesRepository = new CategoriesRepository();

const categories: Category[] = [];

categoriesRoutes.post("/", (request, response) => {
   const { name, description } = request.body;

   const createCategoryService = new CreateCategoryService(categoriesRepository);

   createCategoryService.execute({name, description})

   return response.status(201).send();
});

categoriesRoutes.get("/", (request, response) => {
   const all = categoriesRepository.list();

   return response.json({ all });
})


export { categoriesRoutes };
