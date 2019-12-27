/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.spring.boot.faceid.authc;

import java.util.Locale;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.biz.web.filter.authc.AbstractLogoutFilter;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.LogoutFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.baomidou.kisso.SSOHelper;

/**
 * FaceID 注销过滤器：清除Shiro状态数据和自身缓存数据
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class FaceIDLogoutFilter extends AbstractLogoutFilter {

    private static final Logger LOG = LoggerFactory.getLogger(LogoutFilter.class);

	@Override
	protected boolean preHandle(ServletRequest request, ServletResponse response)
			throws Exception {
		
		Subject subject = getSubject(request, response);
		
		Exception ex = null;
		boolean result = false;
		try {
			
			// Check if POST only logout is enabled
	        if (isPostOnlyLogout()) {

	            // check if the current request's method is a POST, if not redirect
	            if (!WebUtils.toHttp(request).getMethod().toUpperCase(Locale.ENGLISH).equals("POST")) {
	               return onLogoutRequestNotAPost(request, response);
	            }
	        }
	        
			// do real thing
	        subject.logout();
			result = SSOHelper.clearLogin(WebUtils.toHttp(request), WebUtils.toHttp(response));
		} catch (Exception e) {
			LOG.debug("Encountered session exception during logout.  This can generally safely be ignored.", e);
			ex = e;
		}
		
		if(ex != null){
			throw ex;
		}
		
		return result;
	}
	
}
