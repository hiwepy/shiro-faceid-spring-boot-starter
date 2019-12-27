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

import java.io.IOException;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authc.AuthcResponse;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.filter.authc.AbstractTrustableAuthenticatingFilter;
import org.apache.shiro.biz.web.servlet.http.HttpStatus;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;

import com.alibaba.fastjson.JSONObject;
import com.baomidou.kisso.SSOHelper;
import com.baomidou.kisso.common.SSOConstants;
import com.baomidou.kisso.security.token.SSOToken;
import com.baomidou.kisso.web.handler.KissoDefaultHandler;
import com.baomidou.kisso.web.handler.SSOHandlerInterceptor;

/**
 * Kisso 认证 (authentication)过滤器
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class FaceIDAuthenticatingFilter extends AbstractTrustableAuthenticatingFilter {

	private static final Logger LOG = LoggerFactory.getLogger(FaceIDAuthenticatingFilter.class);
	private SSOHandlerInterceptor handlerInterceptor;
	
	public FaceIDAuthenticatingFilter() {
		super();
	}
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
		// 判断是否无状态
		if (isSessionStateless()) {
			// 获取当前请求 Kisso Token
	        SSOToken ssoToken = SSOHelper.getSSOToken(WebUtils.toHttp(request));
			// 判断是否认证请求  
	        if (ssoToken != null) {
	        	/*
				 * 正常请求，request 设置 token 减少二次解密
				 */
                request.setAttribute(SSOConstants.SSO_TOKEN_ATTR, ssoToken);
				// Step 1、生成Shiro Token 
				AuthenticationToken token = createToken(request, response);
				try {
					//Step 2、委托给Realm进行登录  
					Subject subject = getSubject(request, response);
					subject.login(token);
					//Step 3、执行授权成功后的函数
					return onAccessSuccess(token, subject, request, response);
				} catch (AuthenticationException e) {
					//Step 4、执行授权失败后的函数
					return onAccessFailure(token, e, request, response);
				} 
			}
			// 要求认证
			return false;
		}
		return super.isAccessAllowed(request, response, mappedValue);
	}
	
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		
		// 1、判断是否登录请求 
		if (isLoginRequest(request, response)) {
			
			if (isLoginSubmission(request, response)) {
				if (LOG.isTraceEnabled()) {
					LOG.trace("Login submission detected.  Attempting to execute login.");
				}
				return executeLogin(request, response);
			} else {
				String mString = "Authentication url [" + getLoginUrl() + "] Not Http Post request.";
				if (LOG.isTraceEnabled()) {
					LOG.trace(mString);
				}
				
				WebUtils.toHttp(response).setStatus(HttpStatus.SC_BAD_REQUEST);
				response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
				
				// Response Authentication status information
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.fail(mString));
				
				return false;
			}
		}
		// 2、未授权情况
		else {
			
			String mString = "Attempting to access a path which requires authentication. ";
			if (LOG.isTraceEnabled()) { 
				LOG.trace(mString);
			}
			
			// Ajax 请求：响应json数据对象
			if (WebUtils.isAjaxRequest(request)) {
				
				WebUtils.toHttp(response).setStatus(HttpStatus.SC_UNAUTHORIZED);
				response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
				
				// Response Authentication status information
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.fail(mString));
				
				return false;
			}
			// 普通请求：重定向到登录页
			saveRequestAndRedirectToLogin(request, response);
			return false;
		}
	}
	
	@Override
	protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request,
			ServletResponse response) {
		
		HttpServletRequest httpRequest = WebUtils.toHttp(request);
		HttpServletResponse httpResponse = WebUtils.toHttp(response);
		
		// Ajax 请求：响应json数据对象
		if (WebUtils.isAjaxResponse(request)) {
			
			if(this.getHandlerInterceptor() != null) {
	    		/*
	             * Handler 处理 AJAX 请求
				 */
	            this.getHandlerInterceptor().preTokenIsNullAjax(httpRequest, httpResponse);
	            return false;
	    	}

			super.writeFailureString(token, e, request, response);

			return false;
		}
		
		if(this.getHandlerInterceptor() != null) {
			/*
			 * token 为空，调用 Handler 处理
			 * 返回 true 继续执行，清理登录状态并重定向至登录界面
			 */
	        if (this.getHandlerInterceptor().preTokenIsNull(httpRequest, httpResponse)) {
	            LOG.debug("logout. request url:" + httpRequest.getRequestURL());
				try {
					SSOHelper.clearRedirectLogin(httpRequest, httpResponse);
				} catch (IOException e1) {
					e1.printStackTrace();
				}
	        }
	       
		} else {
			
			// 普通请求：重定向到登录页
			try {
				saveRequestAndRedirectToLogin(request, response);
			} catch (IOException e1) {
				e1.printStackTrace();
			}
			
		}
		return false;
	}
	
	public SSOHandlerInterceptor getHandlerInterceptor() {
        if (handlerInterceptor == null) {
            return KissoDefaultHandler.getInstance();
        }
        return handlerInterceptor;
    }

    public void setHandlerInterceptor(SSOHandlerInterceptor handlerInterceptor) {
        this.handlerInterceptor = handlerInterceptor;
    }

}
