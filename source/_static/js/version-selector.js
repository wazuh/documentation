jQuery(function($) {
  /*
  * Wazuh documentation - Version selector script
  * Copyright (C) 2019 Wazuh, Inc.
  *
  * EXECUTION FLOW
  * ==============
  *
  * 1. VARS: Versions main constants
  *    - currentVersion
  *    - versions
  *
  * 2. FUNC: Adds the current version to the selector button
  *    - checkCurrentVersion()
  *
  * 3. FUNC: Adds the notice "Latest version
  *    - checkLatestDocs()
  *
  * 4. FUNC: Creates the correct links to all the releases
  *    - addVersions()
  *
  *    | 5. FUNC: Normalize a given URL so it comply with a standard format
  *    |    - normalizeUrl()
  *    |
  *    | 6. FUNC: Get the redirection history
  *    |    - getRedirectionHistory()
  *
  *         | 7. FUNC: Get the release key number
  *         |    - getReleaseNum()
  *         |
  *         | 8. FUNC: Return redirections about a URL
  *         |    - getInfoRedirectUrl()
  *         |
  *         | 9. FUNC: Get the logic of the redirects
  *         |    - getLogicRedirects()
  *         |
  *         | 10. FUNC: Find the all the URLs
  *         |    - fillUrls()
  *
  *              | 11. FUNC: Find the following URL
  *              |    - findNextUrl()
  *              |
  *              | 12. FUNC: Find the previous URL
  *              |    - findPrevUrl()
  *
  *         | 13. FUNC: Return the release when a URL is new
  *         |    - getInfoNewsUrl()
  *         |
  *         | 14. FUNC: Return the release when a URL was removed
  *         |    - getInfoRemovedUrl()
  *
  * 15. FUNC: Initialize the tooltip of bootstrap
  *    - tooltip()
  *
  */

  /* Versions main constants */
  const currentVersion = '3.11';
  const versions = [
    {name: '3.11 (current)', url: '/'+currentVersion},
    {name: '3.10', url: '/3.10'},
    {name: '3.9', url: '/3.9'},
    {name: '3.8', url: '/3.8'},
    {name: '3.7', url: '/3.7'},
    {name: '3.6', url: '/3.6'},
    {name: '3.5', url: '/3.5'},
    {name: '3.4', url: '/3.4'},
    {name: '3.3', url: '/3.3'},
    {name: '3.2', url: '/3.2'},
    {name: '3.1', url: '/3.1'},
    {name: '3.0', url: '/3.0'},
    {name: '2.1', url: '/2.1'},
  ];

  /* Adds the current version to the selector button */
  checkCurrentVersion();

  /* Adds the notice "Latest version" */
  checkLatestDocs();

  /* Creates the correct links to all the releases */
  addVersions();
  $(window).on('hashchange', function() {
    addVersions();
  });

  /* Initialize the tooltip of bootstrap */
  $('#select-version [data-toggle="tooltip"]').tooltip();

  /**
   * Add the current version to the version selector
   */
  function checkCurrentVersion() {
    let selected = -1;
    let path = document.location.pathname.replace(/\/{2,}/, '/').split('/')[1];
    const selectVersionCurrent = $('#select-version .current');
    if (path == 'current' || path == '3.x' ) {
      path = currentVersion;
    }
    for (let i = 0; i < versions.length; i++) {
      if ( versions[i].url == '/' + path ) {
        selected = i;
      }
    }
    selectVersionCurrent.html(versions[selected].name);
  }

  /**
    * Shows a warning message to the user if current doc version is not the latest version.
    * Note: For this to work, it requires the documentation version variable (in file conf.py)
    * and the array of versions (in this script) to be updated.
    */
  function checkLatestDocs() {
    const thisVersion = document.querySelector('.no-latest-notice').getAttribute('data-version');
    const latestVersion = versions[0].url.replace('/', '');
    let page = '';
    if ( thisVersion !== latestVersion ) {
      const pageID = document.querySelector('#page');
      pageID.classList.add('no-latest-docs');
    }

    /* Updates link to the latest version with the correct path (documentation's home) */
    page = document.location.pathname.split('/'+thisVersion)[1];
    const link = document.querySelector('.link-latest');
    link.setAttribute('href', 'https://' + window.location.hostname + '/' + latestVersion + page);
  }

  /**
   * Adds the available versions to the version selector.
   */
  function addVersions() {
    let ele = '';
    const selectVersionUl = $('#select-version .dropdown-menu');
    let path = document.location.pathname.replace(/\/{2,}/, '/').split('/')[1];
    let fullUrl = window.location.href;
    let page = '';
    let paramDivision = [];
    let param = '';
    if (fullUrl == null) {
      fullUrl = document.URL; /* Firefox fix */
    }
    page = fullUrl.split('/'+path)[1];
    paramDivision = page.split('?');
    page = normalizeUrl(paramDivision[0]);
    param = paramDivision.length == 2 ? ('?'+paramDivision[1]) : '';

    if (path == 'current' || path == '3.x' ) {
      path = currentVersion;
    }

    /* Creates the links to others versions */
    let href;
    let tooltip;
    let ver;
    let versionsClean = versions.map(function(i) {
      return (i.name).split(' (current)')[0];
    });

    /* Normalize URLs in arrays */
    for (let i = 0; i < versionsClean.length; i++) {
      if ( newUrls[versionsClean[i]] ) {
        newUrls[versionsClean[i]] = newUrls[versionsClean[i]].map(function(url) {
          return normalizeUrl(url);
        });
      }
      if ( removedUrls[versionsClean[i]] ) {
        removedUrls[versionsClean[i]] = removedUrls[versionsClean[i]].map(function(url) {
          return normalizeUrl(url);
        });
      }
    }

    for (let i = 0; i < redirections.length; i++) {
      for ( release in redirections[i] ) {
        if (Object.prototype.hasOwnProperty.call(redirections[i], release)) {
          redirections[i][release] = normalizeUrl(redirections[i][release]);
        }
      }
    }

    /* Get the redirection history */
    const redirHistory = getRedirectionHistory(versionsClean, path, page, newUrls, redirections, removedUrls);
    versionsClean = versionsClean.reverse();

    /* Print the correct links in the selector */
    for (let i = 0; i < versions.length; i++) {
      href = '';
      tooltip = '';
      ver = versionsClean[i];
      if ( redirHistory[ver] != null && redirHistory[ver].length ) {
        href = '/'+ver+redirHistory[ver]+param;
      } else {
        tooltip = 'class="disable" data-toggle="tooltip" data-placement="left" title="This page is not available in version ' + versions[i].name +'"';
      }
      ele += '<li><a href="' + href + '" '+ tooltip +'>'+versions[i].name+'</a></li>';
      if (ver == currentVersion) {
        $('.no-latest-notice .link-latest').attr('href', href);
      }
    }
    selectVersionUl.html(ele);
  }

  /**
   * Normalize a given URL so it comply with a standard format
   * @param {string} originalUrl Partial URL of the page that requires normalization
   * @return {string} The standard (valid) version of the original URL
   */
  function normalizeUrl(originalUrl) {
    if (!Array.isArray(originalUrl)) {
      let normalizedURL = originalUrl.trim().replace('index.html', '');
      normalizedURL = normalizedURL.replace(/\/{2,}/, '/');

      if (normalizedURL.charAt(normalizedURL.length-1) == '#' ) {
        normalizedURL = normalizedURL.substring(0, normalizedURL.length-1);
      }

      if (normalizedURL.charAt(normalizedURL.length-1) != '/' && !(/.*(\.html|#.*)$/.test(normalizedURL))) {
        normalizedURL = normalizedURL+'/';
      }
      if (normalizedURL.charAt(0) != '/') {
        normalizedURL = '/'+normalizedURL;
      }

      if (!checkEncodeURI(normalizedURL)) {
        normalizedURL = encodeURI(normalizedURL);
      }
      return normalizedURL;
    } else {
      return originalUrl;
    }
  }

  /**
   * Get the redirections history about a URL
   * @param {array} versions A list with all the releases
   * @param {string} verCurrent The current version
   * @param {string} page The current page URL
   * @param {array} newUrls A list with all the new URL
   * @param {array} redirections A list with all the URL redirections
   * @param {array} removedUrls A list with all the URL removed
   * @return {array} A list with the correct URL
   */
  function getRedirectionHistory(versions, verCurrent, page, newUrls, redirections, removedUrls) {
    const rtn = [];
    const historyArray = [];
    historyArray[verCurrent] = page;
    let cellTemp = [];
    versions = versions.reverse();
    const verCurrentNum = getReleaseNum(verCurrent, versions);
    let direction = 'toBoth';
    if (verCurrentNum == versions.length) {
      direction = 'toBottom';
    }
    if (verCurrentNum == 0) {
      direction = 'toTop';
    }

    cellTemp.push({
      'page': page,
      'version': verCurrent,
      'versionNum': verCurrentNum,
      'direction': direction,
    });

    let count = 0;
    while (cellTemp.length) {
      const analyzeUrl = cellTemp.pop();
      let infoUrl = getInfoRedirectUrl(analyzeUrl['page'], redirections);
      let logic = getLogicRedirects(analyzeUrl, infoUrl, versions);
      if (logic.length == 0) {
        const pageHashArray = analyzeUrl['page'].split('#');
        if ( pageHashArray.length > 1 ) {
          infoUrl = getInfoRedirectUrl(pageHashArray[0], redirections);
          if (infoUrl.length != 0) {
            analyzeUrl['page'] = pageHashArray[0];
          }
        }
        logic = getLogicRedirects(analyzeUrl, infoUrl, versions);
      }
      while (logic.length) {
        const forLogic = logic.pop();
        const p = forLogic['url'];
        const v = forLogic['release'];
        const d = forLogic['direction'];
        const vn = getReleaseNum(forLogic['release'], versions);
        const urlNew = {
          'page': p,
          'version': v,
          'versionNum': vn,
          'direction': d,
        };
        cellTemp.push(urlNew);
        historyArray[v] = p;
      }
      if (count >= 1000) {
        cellTemp = [];
        return false;
      }
      count++;
    }

    historyArray1 = fillUrls('toBottom', historyArray, verCurrentNum, versions);
    historyArray2 = fillUrls('toTop', historyArray, verCurrentNum, versions);

    for (x in historyArray1) {
      if ({}.hasOwnProperty.call(historyArray1, x)) {
        rtn[x] = historyArray1[x];
      }
    }
    for (x in historyArray2) {
      if ({}.hasOwnProperty.call(historyArray2, x)) {
        rtn[x] = historyArray2[x];
      }
    }

    const pageCreated = getInfoNewsUrl(rtn[versions[0]], newUrls);
    if (pageCreated !== false) {
      const pageCreatedNum = getReleaseNum(pageCreated['release'], versions);
      for (r in rtn) {
        if ({}.hasOwnProperty.call(rtn, r)) {
          const rNum = getReleaseNum(r, versions);
          if (parseInt(rNum) < parseInt(pageCreatedNum)) {
            delete rtn[r];
          }
        }
      }
    }

    const pageRemoved = getInfoRemovedUrl(rtn[versions[versions.length-1]], removedUrls);
    if (pageRemoved !== false) {
      const pageRemovedNum = getReleaseNum(pageRemoved['release'], versions);
      for (r in rtn) {
        if ({}.hasOwnProperty.call(rtn, r)) {
          const rNum = getReleaseNum(r, versions);
          if (parseInt(rNum) >= parseInt(pageRemovedNum)) {
            delete rtn[r];
          }
        }
      }
    }

    return rtn;
  }

  /**
   * Get the release key number
   * @param {string} key The release number
   * @param {array} versions A list with all the releases
   * @return {number} The key number
   */
  function getReleaseNum(key, versions) {
    let verKey = -1;
    for (i in versions) {
      if (key == versions[i]) {
        verKey = i;
      }
    }
    return verKey;
  }

  /**
   * Return redirections about a URL
   * @param {string} page The page URL
   * @param {array} redirections A list with all the redirections
   * @return {array} A list with the redirections related with the page URL
   */
  function getInfoRedirectUrl(page, redirections) {
    const redirectionsTemp = [];
    for (forId in redirections) {
      if ({}.hasOwnProperty.call(redirections, forId)) {
        for (forRelease in redirections[forId]) {
          if (forRelease != 'target') {
            if (page == redirections[forId][forRelease]) {
              redirectionsTemp.push(redirections[forId]);
            }
          }
        }
      }
    }
    return redirectionsTemp;
  }

  /**
   * Return the release when a URL is new
   * @param {string} page The page URL
   * @param {array} newUrls A list with all the new pages
   * @return {array|boolean} A list with the new pages related with the page URL
   */
  function getInfoNewsUrl(page, newUrls) {
    let newUrlsTemp = false;
    for (forRelease in newUrls) {
      if ({}.hasOwnProperty.call(newUrls, forRelease)) {
        for (forUrl in newUrls[forRelease]) {
          if ({}.hasOwnProperty.call(newUrls[forRelease], forUrl)) {
            const pageWithoutHash = page.split('#')[0];
            if (pageWithoutHash == newUrls[forRelease][forUrl]) {
              newUrlsTemp = [];
              newUrlsTemp['release'] = forRelease;
              newUrlsTemp['url'] = newUrls[forRelease][forUrl];
            }
          }
        }
      }
    }
    return newUrlsTemp;
  }

  /**
   * Return the release when a URL was removed
   * @param {string} page The page URL
   * @param {array} removedUrls A list with all the removed pages
   * @return {array|boolean} A list with the removeds pages related with the page URL
   */
  function getInfoRemovedUrl(page, removedUrls) {
    let removedUrlsTemp = false;
    for (forRelease in removedUrls) {
      if ({}.hasOwnProperty.call(removedUrls, forRelease)) {
        for (forUrl in removedUrls[forRelease]) {
          if ({}.hasOwnProperty.call(removedUrls[forRelease], forUrl)) {
            const pageWithoutHash = page.split('#')[0];
            if (pageWithoutHash == removedUrls[forRelease][forUrl]) {
              removedUrlsTemp = [];
              removedUrlsTemp['release'] = forRelease;
              removedUrlsTemp['url'] = removedUrls[forRelease][forUrl];
            }
          }
        }
      }
    }
    return removedUrlsTemp;
  }

  /**
   * Get the logic of the redirects
   * @param {array} analyzeUrl Info about the current URL
   * @param {array} infoUrl A list with the redirections related with the page URL
   * @param {array} versions A list with all the releases
   * @return {array} A list with the URL related with the redirections of the current URL
   */
  function getLogicRedirects(analyzeUrl, infoUrl, versions) {
    const relatedUrl = [];
    const infoUrlRedirects = infoUrl;
    while (infoUrlRedirects.length) {
      const redirect = infoUrlRedirects.pop();
      for (forTarget in redirect['target']) {
        if ({}.hasOwnProperty.call(redirect['target'], forTarget)) {
          const target = redirect['target'][forTarget].split('=>');
          const originNum = parseInt(getReleaseNum(target[0], versions));
          const targetNum = parseInt(getReleaseNum(target[1], versions));
          if (analyzeUrl['page'] == redirect[target[0]]) {
            /* To top */
            if (
              analyzeUrl['direction'] != 'toBottom'
              &&
              originNum < targetNum
              &&
              parseInt(analyzeUrl['versionNum']) <= originNum
            ) {
              relatedUrl.push({
                'release': target[1],
                'direction': 'toTop',
                'url': redirect[target[1]],
              });
            }
            /* To bottom */
            if (
              analyzeUrl['direction'] != 'toTop'
              &&
              originNum > targetNum
              &&
              parseInt(analyzeUrl['versionNum']) >= originNum
            ) {
              relatedUrl.push({
                'release': target[1],
                'direction': 'toBottom',
                'url': redirect[target[1]],
              });
            }
          }
        }
      }
    }
    return relatedUrl;
  }

  /**
   * Find the all the URLs
   * @param {string} direction Indicate the direction to analize the URL array
   * @param {array} historyArray A array with the URL found
   * @param {number} verCurrentNum The number of the current release
   * @param {array} versions A list with all the releases
   * @return {array} A array with all the URL found
   */
  function fillUrls(direction, historyArray, verCurrentNum, versions) {
    const historyArrayTemp = [];
    for (forVersions in versions) {
      if ({}.hasOwnProperty.call(versions, forVersions)) {
        forVersions = parseInt(forVersions);

        if (direction == 'toBottom') {
          if (forVersions < verCurrentNum) {
            if (historyArray[versions[forVersions]] == null) {
              /* If the checked version is smaller than the larger version */
              if (forVersions != versions.length-1) {
                const next = findNextUrl(forVersions, versions, historyArray);
                if (next != -1) {
                  historyArrayTemp[versions[forVersions]] = historyArray[versions[next]];
                }
              }
            } else {
              historyArrayTemp[versions[forVersions]] = historyArray[versions[forVersions]];
            }
          }
        }
        if (direction == 'toTop') {
          if (forVersions >= verCurrentNum) {
            if (historyArray[versions[forVersions]] == null) {
              /* If the tested version is larger than the first version */
              if (forVersions != 0) {
                const prev = findPrevUrl(forVersions, versions, historyArrayTemp);
                if (prev != -1) {
                  historyArrayTemp[versions[forVersions]] = historyArrayTemp[versions[prev]];
                }
              }
            } else {
              historyArrayTemp[versions[forVersions]] = historyArray[versions[forVersions]];
            }
          }
        }
      }
    }
    return historyArrayTemp;
  }

  /**
   * Find the following URL
   * @param {number} num The key number of the current release
   * @param {number} versions A list with all the releases
   * @param {number} historyArray A list with the URL found
   * @return {number} The key number of the next release
   */
  function findNextUrl(num, versions, historyArray) {
    let found = -1;
    for (i in versions) {
      if ({}.hasOwnProperty.call(versions, i)) {
        i = parseInt(i);
        if (i > num) {
          if (historyArray[versions[i]] != null && found == -1) {
            found = i;
          }
        }
      }
    }
    return found;
  }

  /**
   * Find the previous URL
   * @param {number} num The key number of the current release
   * @param {number} versions A list with all the releases
   * @param {number} historyArrayTemp A list with the URL found
   * @return {number} The key number of the previous release
   */
  function findPrevUrl(num, versions, historyArrayTemp) {
    let found = -1;
    for (i in versions) {
      if ({}.hasOwnProperty.call(versions, i)) {
        i = parseInt(i);
        if (i >= num) {
          if (historyArrayTemp[versions[i-1]] != null && found == -1) {
            found = i-1;
          }
        }
      }
    }
    return found;
  }
});

/**
 * Checks if a URI is encoded
 * @param {string} str string containing the URI to be checked
 * @return {boolean} True if the URL seems to be encoded
 */
function checkEncodeURI(str) {
  return /\%/i.test(str);
}
