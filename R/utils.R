#' @title Remove bearer from token
#' @description Removes the "Bearer " prefix from a token
#'
#' @param token A string containing the token
#'
#' @return A string containing the token without the "Bearer " prefix
#' @keywords internal
remove_bearer <- function(token) {
  if (is.null(token)) {
    return(NULL)
  }
  token <- stringr::str_remove(token, "^Bearer ")
  return(token)
}

#' @title Build a cookie
#' @description Builds an HttpOnly cookie from a key and value
#'
#' @param key A string containing the cookie key
#' @param value A string containing the cookie value
#'
#' @return A string containing the cookie
#' @keywords internal
build_cookie <- function(key, value) {
  glue::glue("{key}={value}; path=/; SameSite=Lax; HttpOnly")
}

map_null <- function(x, f) {
  if (is.null(x)) {
    return(NULL)
  }
  return(f(x))
}

add_trailing_slash_to_path <- function(path) {
  if (!stringr::str_ends(path, "/")) {
    path <- glue::glue("{path}/")
  }
  return(path)
}

if_length_0 <- function(x, y) {
  if (length(x) == 0) {
    return(y)
  }
  return(x)
}

#' @title Add trailing slash to URL
#' @description If the app URL does not end with a slash, this function
#'   will add one.
#'
#' @param url A string containing a URL
#'
#' @return A string containing the URL with a trailing slash
#' @keywords internal
add_trailing_slash <- function(url) {
  url <- httr2::url_parse(url)
  url$path <- url$path |>
    map_null(add_trailing_slash_to_path) |>
    if_length_0("/")
  httr2::url_build(url)
}

#' @title Build a redirect URI
#' @description Builds a redirect URI from an app URL
#'
#' @param app_url A string containing the app URL with a trailing slash
#'
#' @return A string containing the redirect URI
#' @keywords internal
build_redirect_uri <- function(app_url) {
  url <- httr2::url_parse(app_url)
  path <- url$path
  url$path <- glue::glue("{path}login")
  httr2::url_build(url)
}
