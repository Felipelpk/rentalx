import { CategoriesRepository } from "../repositories/CategoriesRepository";

interface IRequest {
    name: string;
    description: string;
}

/**
 * [X] - Definir o tipo de retorno
 * [X] - Alterar o retorno de erro
 * [X] - Acessar o repositorio
 * [X] - Retornar algo
 */

class CreateCategoryService { 
    constructor(private categoriesRepository: CategoriesRepository) {
    }

    execute({ name,description }: IRequest): void {
        const categoryAlreadyExists = this.categoriesRepository.findByName(name);

        if(categoryAlreadyExists){
            throw new Error("Category Already exists!")
        }

        this.categoriesRepository.create({name, description})

    }
}

export { CreateCategoryService }