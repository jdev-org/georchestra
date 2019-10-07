require('components/orgs/orgs.tpl')
require('services/orgs')

class OrgsController {
  static $inject = [ '$injector', '$routeParams' ]

  constructor ($injector, $routeParams) {
    this.$injector = $injector

    this.org = $routeParams.org
    this.orgs = this.$injector.get('Orgs').query(() => {
      if (this.org === 'pending') {
        this.orgs = this.orgs.filter(o => o.pending)
      } else {
        // display no pendings orgs
        this.orgs = this.orgs.filter(o => !o.pending)
      }
      this.orgs.forEach(org => {
        org.membersCount = org.members.length
        delete org.members
      })
    })

    this.q = ''
    this.itemsPerPage = 15

    this.newOrg = this.$injector.get('$location').$$search['new'] === 'org'
    if (this.newOrg) {
      const Org = this.$injector.get('Orgs')
      this.newInstance = new Org({})
    }

    this.required = $injector.get('OrgsRequired').query()
    this.orgTypeValues = $injector.get('OrgsType').query()

    let translate = this.$injector.get('translate')
    this.i18n = {}
    translate('org.created', this.i18n)
    translate('org.updated', this.i18n)
    translate('org.deleted', this.i18n)
    translate('org.error', this.i18n)
    translate('org.deleteError', this.i18n)
  }

  export_ (fileType) {
    const download = this.$injector.get(`ExportOrgs${fileType.toUpperCase()}`)
    const filter = this.$injector.get('$filter')
    download(filter('filter')(this.orgs, this.q).map(o => o.id)).then(result => {
      if (result.status !== 200) {
        throw new Error(`Cannot fetch orgs list. error ${result.status}`)
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
      a.download = `${date}_orgs_export.${fileType}`
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
    const Org = this.$injector.get('Orgs')
    this.newInstance = new Org({})
    let $location = this.$injector.get('$location')
    $location.search('new', 'org')
  }

  saveOrg () {
    let flash = this.$injector.get('Flash')
    let $router = this.$injector.get('$router')
    let $location = this.$injector.get('$location')
    let $httpDefaultCache = this.$injector.get('$cacheFactory').get('$http')

    this.newInstance.$save(
      () => {
        flash.create('success', this.i18n.created)
        $httpDefaultCache.removeAll()
        $router.navigate($router.generate('org', {
          org: this.newInstance.id,
          tab: 'infos'
        }))
        $location.url($location.path())
      },
      flash.create.bind(flash, 'danger', this.i18n.error)
    )
  }

  close () {
    this.newOrg = false
    let $location = this.$injector.get('$location')
    $location.url($location.path())
  }

  activate ($scope) {
    let $location = this.$injector.get('$location')
    $scope.$watch(() => $location.search()['new'], (v) => {
      this.newOrg = v === 'org'
    })
  }
}

OrgsController.prototype.activate.$inject = [ '$scope' ]

angular.module('manager').controller('OrgsController', OrgsController)
