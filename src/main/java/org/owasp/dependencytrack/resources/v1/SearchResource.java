/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencytrack.resources.v1;

import alpine.auth.PermissionRequired;
import alpine.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.owasp.dependencytrack.auth.Permission;
import org.owasp.dependencytrack.search.SearchManager;
import org.owasp.dependencytrack.search.SearchResult;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * JAX-RS resources for processing search requests.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/search")
@Api(value = "search", authorizations = @Authorization(value = "X-Api-Key"))
public class SearchResource extends AlpineResource {

    @GET
    @Path("/{query}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Processes and returns search results",
            response = SearchResult.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permission.PROJECT_VIEW)
    public Response search(@PathParam("query") String query) {
        final SearchManager searchManager = new SearchManager();
        final SearchResult searchResult = searchManager.searchIndices(query, 10);
        return Response.ok(searchResult).build();
    }

}
