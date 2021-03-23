// Copyright Project Harbor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
import { Injectable } from '@angular/core';
import {
  CanActivate, Router,
  ActivatedRouteSnapshot,
  RouterStateSnapshot,
  CanActivateChild
} from '@angular/router';
import { SessionService } from '../../shared/session.service';
import { CommonRoutes } from '../../shared/shared.const';
import {AppConfigService} from "../../app-config.service";
import {AppConfig} from "../../app-config";

@Injectable()
export class SignInGuard implements CanActivate, CanActivateChild {
  constructor(private authService: SessionService, private router: Router, private appConfigService: AppConfigService) { }

  canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Promise<boolean> | boolean {
    // If user has logged in, should not login again
    return new Promise((resolve, reject) => {
        let appconfig = this.appConfigService.configurations;
        this.appConfigService.load()
            .then(updatedConfig => {
                appconfig = updatedConfig;
            })
            .catch(error => {
                console.error("Failed to load bootstrap options with error: ", error);
                window.alert("load config error");
            });
        // 天使系统配置信息
        let angel_endpoint = appconfig.angel_endpoint;
        let angel_redirect = appconfig.angel_redirect;
        const angel_redirect_url = angel_endpoint + "/#/login?service=" + angel_redirect;
      // If signout appended
      let queryParams = route.queryParams;
      if (queryParams && queryParams['signout']) {
        this.authService.signOff()
          .then(() => {
            this.authService.clear(); // Destroy session cache
              window.location.href = angel_redirect_url;
            return resolve(false);
          })
          .catch(error => {
            console.error(error);
            return resolve(false);
          });
      } else {
        let user = this.authService.getCurrentUser();
        if (user === null) {
          this.authService.retrieveUser()
            .then(() => {
              this.router.navigate([CommonRoutes.HARBOR_DEFAULT]);
              return resolve(false);
            })
            .catch(error => {
              // 判断是否是天使认证
                if (appconfig.auth_mode === "angel_auth") {
                    if (!state.url.includes("token=")) {
                        window.location.href = angel_redirect_url;
                        return resolve(false);
                    } else {
                        // 已经获得天使token，进行后台认证
                        let token = state.url.substring(state.url.indexOf("token=") + 6);
                        // 获取初始访问url
                        // let redirectUrl = "";
                        // route.queryParams
                        //     .subscribe(params => {
                        //       redirectUrl = params["redirect_url"] || "";
                        //     });
                        this.authService.signInByToken(token)
                            .then(() => {
                                // Redirect to the right route
                                // if (redirectUrl === "") {
                                // Routing to the default location
                                // this.router.navigateByUrl(CommonRoutes.HARBOR_DEFAULT);
                                // } else {
                                //   this.router.navigateByUrl(redirectUrl);
                                // }
                                this.router.navigateByUrl(CommonRoutes.HARBOR_DEFAULT);
                                return resolve(false);
                            }).catch(error1 => {
                            window.location.href = angel_redirect_url;
                            return resolve(false);
                        });
                    }
                } else {
                    return resolve(true);
                }
            });
        } else {
          this.router.navigate([CommonRoutes.HARBOR_DEFAULT]);
          return resolve(false);
        }
      }
    });
  }

  canActivateChild(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Promise<boolean> | boolean {
    return this.canActivate(route, state);
  }
}
