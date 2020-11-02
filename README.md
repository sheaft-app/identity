# Sheaft Identity (basé sur IdentityServer4)

Ce projet permet de gérer les comptes utilisateurs de la plateforme Sheaft, il est configurée pour permettre la connexion via un compte local (créer sur https://auth.sheaft.com) ou via un compte externe (Facebook, Google et Microsoft).

## Pré-requis

- Entity Framework Core CLI: https://docs.microsoft.com/en-us/ef/core/miscellaneous/cli/dotnet 
- Un container SQL docker avec l'image suivante: "docker run --name app -e 'ACCEPT_EULA=Y' -e 'SA_PASSWORD=##REPLACE##' -p 1434:1433 -d mcr.microsoft.com/mssql/server:2019-latest". Le port docker est redirigé sur 1434 pour ne pas interférer avec un serveur SQL déjà présent sur la machine.
- SQLLocalDb/Express si vous possédez déjà une instance configurée et ne souhaitez pas utiliser docker (pensez à mettre à jour le port dans le fichier appsettings.json).
- dotnet core 3.1 : https://dotnet.microsoft.com/download/dotnet-core/3.1
- Un compte Amazon SES: https://aws.amazon.com/fr/ses/
- Des providers de connexion externe.

## Enpoints appelés par l'api de sheaft

- PUT Account/Profile -> Mets à jour les informations du compte (dont les rôles)
- PUT Account/Picture - Mets à jour uniquement l'image du profil
- DELETE Account/UserAccount -> Supprime le compte de la plateforme d'authentification

Ces endpoints sont appelés avec un header: Authorization: apikey ##REPLACE##

## Evolution du modèle de base de données

La base de données est mappée à l'aide d'Entity Framework Core. Pour la mettre à jour il faut donc faire les modifications nécessaire sur AuthDbContext puis executer:  dotnet-ef migrations add ##REPLACE## -c AuthDbContext

Vous pouvez ensuite appliquer la migration à l'aide de la commande suivante: dotnet-ef database update ##REPLACE###

Vous pouvez annuler la dernière migration si celle-ci n'a pas été appliquée via:  dotnet-ef migrations remove -c AuthDbContext
