import 'components/roles/roles.tpl'
import 'services/roles'

class RolesController {
  static $inject = [ '$injector', '$routeParams' ]

  constructor ($injector, $routeParams) {
    this.$injector = $injector

    this.role = $routeParams.role
    this.roles = this.$injector.get('Role').query(() => {
      this.roles.forEach(r => {
        r.usersCount = r.users.length
        delete r.users
      })
    })

    this.q = ''
    this.itemsPerPage = 15

    this.newRole = this.$injector.get('$location').$$search['new'] === 'role'
    if (this.newRole) {
      const Role = this.$injector.get('Role')
      this.newInstance = new Role({})
    }

    let translate = this.$injector.get('translate')
    this.i18n = {}
    translate('role.created', this.i18n)
    translate('role.updated', this.i18n)
    translate('role.deleted', this.i18n)
    translate('role.error', this.i18n)
    translate('role.deleteError', this.i18n)
  }

  export_ (fileType) {
    const download = this.$injector.get(`Export${fileType.toUpperCase()}`)
    const filter = this.$injector.get('$filter')
    download(filter('filter')(this.roles, this.q).map(r => r.cn)).then(result => {
      if (result.status !== 200) {
        throw new Error(`Cannot fetch roles list. error ${result.status}`)
      }
      let mimetype = ''
      switch (fileType) {
        case 'vcf':
          mimetype = 'text/x-vcard'
          break
        default:
          mimetype = `text/${fileType};charset=utf-8`
      }
      const blob = new Blob(['\ufeff', result.data], { type: mimetype })
      const a = document.createElement('a')
      a.href = window.URL.createObjectURL(blob)
      a.target = '_blank'
      const date = filter('date')(new Date(), 'yyyyMMdd-HHmmss')
      a.download = `${date}_roles_export.${fileType}`
      document.body.appendChild(a) // create the link "a"
      a.click() // click the link "a"
      document.body.removeChild(a)
    }).catch(err => {
      let flash = this.$injector.get('Flash')
      flash.create('danger', err)
    })
  }

  exportCSV () {
    this.export_('csv')
  }

  exportVCF () {
    this.export_('vcf')
  }

  create () {
    const Role = this.$injector.get('Role')
    this.newInstance = new Role({})
    let $location = this.$injector.get('$location')
    $location.search('new', 'role')
  }

  saveRole () {
    let flash = this.$injector.get('Flash')
    let $router = this.$injector.get('$router')
    let $location = this.$injector.get('$location')
    let $httpDefaultCache = this.$injector.get('$cacheFactory').get('$http')

    this.newInstance.$save(
      () => {
        flash.create('success', this.i18n.created)
        $httpDefaultCache.removeAll()
        $router.navigate($router.generate('role', {
          role: this.newInstance.cn,
          tab: 'infos'
        }))
        $location.url($location.path())
      },
      flash.create.bind(flash, 'danger', this.i18n.error)
    )
  }

  close () {
    this.newRole = false
    let $location = this.$injector.get('$location')
    $location.url($location.path())
  }

  activate ($scope) {
    let $location = this.$injector.get('$location')
    $scope.$watch(() => $location.search()['new'], (v) => {
      this.newRole = v === 'role'
    })
  }
}

RolesController.prototype.activate.$inject = [ '$scope' ]

angular.module('manager').controller('RolesController', RolesController)
