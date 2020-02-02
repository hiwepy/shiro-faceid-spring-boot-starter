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

import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authc.AuthenticationSuccessHandler;
import org.apache.shiro.biz.authz.principal.ShiroPrincipal;
import org.apache.shiro.biz.utils.SubjectUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.spring.boot.faceid.token.FaceIDLoginToken;
import org.apache.shiro.subject.Subject;

import com.google.common.collect.Maps;

public class FaceIDAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	public FaceIDAuthenticationSuccessHandler() {
	}
	 
	@Override
	public boolean supports(AuthenticationToken token) {
		return SubjectUtils.isAssignableFrom(token.getClass(), FaceIDLoginToken.class);
	}

	@Override
	public void onAuthenticationSuccess(AuthenticationToken token, ServletRequest request, ServletResponse response,
			Subject subject) {
		
		HttpServletRequest httpRequest = WebUtils.toHttp(request);
		HttpServletResponse httpResponse = WebUtils.toHttp(response);

		ShiroPrincipal principal = (ShiroPrincipal) subject.getPrincipal();

		Map<String, Object> map = Maps.newHashMap();
		map.put("userid", principal.getUserid());
		map.put("userkey", principal.getUserkey());
		map.put("username", principal.getUsername());
		map.put("roles", principal.getRoles());
		map.put("perms", principal.getRoles());


	}

}
