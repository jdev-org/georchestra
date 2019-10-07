angular.module('manager')
  .factory('Orgs', ['$resource', 'CONSOLE_PRIVATE_PATH', ($resource, baseUri) =>
    $resource(baseUri + 'orgs/:id', {}, {
      query: {
        cache: true,
        method: 'GET',
        isArray: true
      },
      get: {
        params: { id: '@id' },
        method: 'GET',
        cache: true,
        isArray: false
      },
      update: {
        params: { id: '@id' },
        method: 'PUT'
      },
      delete: {
        params: { id: '@id' },
        method: 'DELETE'
      }
    })
  ]).factory('OrgsRequired', ['$resource', 'CONSOLE_PUBLIC_PATH', ($resource, baseUri) =>
    $resource(baseUri + 'orgs/requiredFields', {}, {
      query: {
        method: 'GET',
        cache: true,
        transformResponse: (data) => {
          let response = {}
          JSON.parse(data).forEach(key => { response[key] = true })
          return response
        }
      }
    })
  ]).factory('OrgsType', ['$resource', 'CONSOLE_PUBLIC_PATH', ($resource, baseUri) =>
    $resource(baseUri + 'orgs/orgTypeValues', {}, {
      query: {
        method: 'GET',
        cache: true,
        isArray: true
      }
    })
  ]).factory('ExportOrgsCSV', ['$http', 'CONSOLE_PRIVATE_PATH', ($http, baseUri) => {
    return orgs => {
      return $http.post(baseUri + 'export/orgs.csv', orgs, {
        cache: false,
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'text/csv'
        }
      })
    }
  }
  ])
