angular.module('manager')
  .factory('Role', ['$resource', 'CONSOLE_PRIVATE_PATH', ($resource, baseUri) =>
    $resource(baseUri + 'roles/:id', {}, {
      query: {
        cache: true,
        method: 'GET',
        isArray: true
      },
      get: {
        isArray: false
      },
      update: {
        params: { id: '@originalID' },
        method: 'PUT'
      },
      delete: {
        params: { id: '@cn' },
        method: 'DELETE'
      }
    })
  ]).factory('roleAdminList', [ () => {
    const adminRoles = [
      'SUPERUSER',
      'ADMINISTRATOR',
      'GN_ADMIN',
      'GN_EDITOR',
      'GN_REVIEWER',
      'ORGADMIN',
      'EXTRACTORAPP',
      'USER',
      'PENDING',
      'REFERENT',
      'TEMPORARY'
    ]
    return () => adminRoles
  }]).factory('roleAdminFilter', [ 'roleAdminList', (roleAdminList) =>
    (role) => roleAdminList().indexOf(role.cn) >= 0
  ]).factory('ExportVCF', ['$http', 'CONSOLE_PRIVATE_PATH', ($http, baseUri) => {
    return roles => {
      return $http.post(baseUri + 'export/roles.vcf', roles, {
        cache: false,
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'text/x-vcard'
        }
      })
    }
  }
  ]).factory('ExportRolesCSV', ['$http', 'CONSOLE_PRIVATE_PATH', ($http, baseUri) => {
    return roles => {
      return $http.post(baseUri + 'export/roles.csv', roles, {
        cache: false,
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'text/csv'
        }
      })
    }
  }
  ])
