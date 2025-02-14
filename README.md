# tapLock

## Example Shiny App with Entra ID Authentication

```R
library(shiny)
library(tapLock)

auth_config <- new_openid_config(
  provider = "entra_id",
  tenant_id = Sys.getenv("TENANT_ID"),
  client_id = Sys.getenv("CLIENT_ID"),
  client_secret = Sys.getenv("CLIENT_SECRET"),
  app_url = Sys.getenv("APP_URL")
)

ui <- fluidPage(
  tags$h1("tapLock example"),
  textOutput("user")
)

server <- function(input, output, session) {

  output$user <- renderText({
    given_name <- get_token_field(token(), "given_name")
    family_name <- get_token_field(token(), "family_name")
    expires_at <- expires_at(token())
    glue::glue(
      "Hello {given_name} {family_name}!",
      "Your authenticated session will expire at {expires_at}.",
      .sep = " "
    )
  })

}
```

## Example Shiny App with Google Authentication

```R
library(shiny)
library(tapLock)

auth_config <- new_openid_config(
  provider = "google",
  client_id = Sys.getenv("CLIENT_ID"),
  client_secret = Sys.getenv("CLIENT_SECRET"),
  app_url = Sys.getenv("APP_URL")
)

ui <- fluidPage(
  tags$h1("tapLock example"),
  textOutput("user")
)

server <- function(input, output, session) {

  output$user <- renderText({
    given_name <- get_token_field(token(), "given_name")
    family_name <- get_token_field(token(), "family_name")
    expires_at <- expires_at(token())
    glue::glue(
      "Hello {given_name} {family_name}!",
      "Your authenticated session will expire at {expires_at}.",
      .sep = " "
    )
  })

}
```

