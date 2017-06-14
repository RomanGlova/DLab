/***************************************************************************

 Copyright (c) 2016, EPAM SYSTEMS INC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

 ****************************************************************************/

package com.epam.dlab.backendapi.dao;

import static com.epam.dlab.backendapi.dao.ComputationalDAO.COMPUTATIONAL_ID;
import static com.epam.dlab.backendapi.dao.ExploratoryDAO.COMPUTATIONAL_RESOURCES;
import static com.epam.dlab.backendapi.dao.ExploratoryDAO.EXPLORATORY_ID;
import static com.epam.dlab.core.parser.ReportLine.FIELD_COST;
import static com.epam.dlab.core.parser.ReportLine.FIELD_CURRENCY_CODE;
import static com.epam.dlab.core.parser.ReportLine.FIELD_DLAB_ID;
import static com.epam.dlab.core.parser.ReportLine.FIELD_PRODUCT;
import static com.epam.dlab.core.parser.ReportLine.FIELD_RESOURCE_TYPE;
import static com.epam.dlab.core.parser.ReportLine.FIELD_USAGE_DATE;
import static com.mongodb.client.model.Accumulators.max;
import static com.mongodb.client.model.Accumulators.min;
import static com.mongodb.client.model.Accumulators.sum;
import static com.mongodb.client.model.Aggregates.group;
import static com.mongodb.client.model.Aggregates.match;
import static com.mongodb.client.model.Aggregates.sort;
import static com.mongodb.client.model.Filters.and;
import static com.mongodb.client.model.Filters.eq;
import static com.mongodb.client.model.Projections.excludeId;
import static com.mongodb.client.model.Projections.fields;
import static com.mongodb.client.model.Projections.include;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bson.Document;
import org.bson.conversions.Bson;

import com.epam.dlab.backendapi.resources.dto.BillingFilterFormDTO;
import com.epam.dlab.core.BillingUtils;
import com.epam.dlab.mongo.DlabResourceType;
import com.google.common.base.MoreObjects;
import com.google.inject.Inject;
import com.mongodb.client.AggregateIterable;
import com.mongodb.client.FindIterable;

/** DAO for user billing.
 */
public class BillingDAO extends BaseDAO {
    private static final String SHAPE = "shape";
    private static final String MASTER_NODE_SHAPE = "master_node_shape";
    private static final String SLAVE_NODE_SHAPE = "slave_node_shape";
    private static final String TOTAL_INSTANCE_NUMBER = "total_instance_number";
    private static final String DLAB_RESOURCE_TYPE = "dlab_resource_type";
	private static final String USAGE_DATE_START = "usage_date_start";
	private static final String USAGE_DATE_END = "usage_date_end";
	
	@Inject
	private SettingsDAO settings;
    
	/** Store shape info */
    private class ShapeInfo {
    	String shape;
    	String slaveShape;
    	String slaveCount;
    	boolean isExploratory;
    	
    	public ShapeInfo(String shape) {
    		this.shape = shape;
    		this.isExploratory = true;
    	}

    	public ShapeInfo(String shape, String slaveShape, String slaveCount) {
    		this.shape = shape;
    		this.slaveShape = slaveShape;
    		this.slaveCount = slaveCount;
    		this.isExploratory = false;
		}
    	
    	@Override
    	public String toString() {
    		return MoreObjects.toStringHelper(this)
    				.add("shape", shape)
    				.add("slaveShape", slaveShape)
    				.add("slaveCount", slaveCount)
    				.add("isExploratory", isExploratory)
    				.toString();
    	}
    }
    
    /** Find and return the map of shape info for exploratory and computational.
     * @param shapeName the name of shape for filter of <b>null</b>.
     */
    private Map<String, ShapeInfo> getShapes(String shapeName) {
    	FindIterable<Document> docs = getCollection(USER_INSTANCES)
    									.find()
    									.projection(
    										fields(excludeId(),
    												include(SHAPE, EXPLORATORY_ID,
    													COMPUTATIONAL_RESOURCES + "." + COMPUTATIONAL_ID,
    													COMPUTATIONAL_RESOURCES + "." + MASTER_NODE_SHAPE,
    													COMPUTATIONAL_RESOURCES + "." + SLAVE_NODE_SHAPE,
    													COMPUTATIONAL_RESOURCES + "." + TOTAL_INSTANCE_NUMBER
    													)));
    	Map<String, ShapeInfo> shapes = new HashMap<>();
    	for (Document d : docs) {
			String name = d.getString(SHAPE);
			if (shapeName == null || shapeName.isEmpty() || shapeName.equals(name)) { 
				shapes.put(d.getString(EXPLORATORY_ID), new ShapeInfo(d.getString(SHAPE)));
			}
			
			@SuppressWarnings("unchecked")
			List<Document> comp = (List<Document>) d.get(COMPUTATIONAL_RESOURCES);
			for (Document c : comp) {
				name = c.getString(MASTER_NODE_SHAPE);
				String slaveName = c.getString(SLAVE_NODE_SHAPE);
				if (shapeName == null || shapeName.isEmpty() ||
					shapeName.equals(name) || shapeName.equals(slaveName)) {
					shapes.put(c.getString(COMPUTATIONAL_ID),
							new ShapeInfo(name, slaveName, c.getString(TOTAL_INSTANCE_NUMBER)));
				}
			}
		}
    	return shapes;
    }
    
    /** Add the condition to the list.
     * @param conditions the list of conditions.
     * @param fieldName the name of field.
     * @param value the value.
     */
    private <TItem> void addCondition(List<Bson> conditions, String fieldName, String value) {
    	if (value != null && !value .isEmpty()) {
    		conditions.add(eq(fieldName, value));
    	}
    }
    
    /** Return field condition for grouping.
     * @param fieldNames the list of field names.
     */
    private Document getGrouppingFields(String ... fieldNames) {
    	Document d = new Document();
		for (String name : fieldNames) {
    		d.put(name, "$" + name);
    	}
		return d;
    }
    
    private String getResourceTypeName(String id) {
    	DlabResourceType resourceTypeId = DlabResourceType.of(id);
    	if (resourceTypeId != null) {
		switch (resourceTypeId) {
			case COMPUTATIONAL:
				return "Cluster";
			case EXPLORATORY:
				return "Notebook";
			case EDGE:
				return "Edge Node";
			case EDGE_BUCKET:
			case SSN_BUCKET:
				return "Bucket";
			case SSN:
				return "SSN";
			}
    	}
		return id;
    }
    
    /** Build and returns the billing report. 
     * @param user name
     * @param filter the filter for report data.
     * @return
     */
    public Document getReport(String user, BillingFilterFormDTO filter) {
    	// Create filter
    	List<Bson> conditions = new ArrayList<>();
    	if (true /*TODO check for admin*/) {
    		user = filter.getUser();
    	}
    	addCondition(conditions, USER, user);
    	addCondition(conditions, FIELD_RESOURCE_TYPE, filter.getProduct());
    	addCondition(conditions, DLAB_RESOURCE_TYPE, filter.getResourceType());
    	addCondition(conditions, FIELD_USAGE_DATE, filter.getDateStart());
    	addCondition(conditions, FIELD_USAGE_DATE, filter.getDateEnd());
    	
    	// Create aggregation conditions
    	List<? extends Bson> pipeline = Arrays.asList(
    			group(getGrouppingFields(USER, FIELD_DLAB_ID, DLAB_RESOURCE_TYPE, FIELD_PRODUCT, FIELD_RESOURCE_TYPE, FIELD_CURRENCY_CODE),
    				sum(FIELD_COST, "$" + FIELD_COST),
    				min(USAGE_DATE_START, "$" + FIELD_USAGE_DATE),
    				max(USAGE_DATE_END, "$" + FIELD_USAGE_DATE)
    				),
    			sort(new Document(ID + "." + USER, 1)
    					.append(ID + "." + FIELD_DLAB_ID, 1)
    					.append(ID + "." + DLAB_RESOURCE_TYPE, 1)
    					.append(ID + "." + FIELD_PRODUCT, 1))
    		);
    	if(conditions.size() > 0) {
    		conditions.add(match(and(conditions)));
    	}

    	// Get billing report and the list of shape info
    	AggregateIterable<Document> agg = getCollection(BILLING).aggregate(pipeline);
    	Map<String, ShapeInfo> shapes = getShapes(filter.getShape());

    	// Build billing report lines
		List<Document> reportItems = new ArrayList<>();
		boolean filterByShape = !(filter.getShape() == null || filter.getShape().isEmpty());
		String usageDateStart = "";
		String usageDateEnd = "";
		double costTotal = 0;
		
		for (Document d : agg) {
			Document id = (Document) d.get(ID);
			String resourceId = id.getString(FIELD_DLAB_ID);
			ShapeInfo shape = shapes.get(resourceId);
			if (filterByShape && shape == null) {
				continue;
			}
			
			String resourceTypeId = getResourceTypeName(id.getString(DLAB_RESOURCE_TYPE));

			String shapeName = "";
			if (shape != null) {
				shapeName = (shape.isExploratory ? shape.shape :
					"Master: " + shape.shape + System.lineSeparator() +
					"Slave:  " + shape.slaveCount + "x" + shape.slaveShape);
			}
			
			String dateStart = d.getString(USAGE_DATE_START);
			if (usageDateStart.compareTo(dateStart) < 0) {
				usageDateStart = dateStart;
			}
			String dateEnd = d.getString(USAGE_DATE_END);
			if (usageDateEnd.compareTo(dateEnd) < 0) {
				usageDateEnd = dateEnd;
			}
			double cost = BillingUtils.round(d.getDouble(FIELD_COST), 2);
			costTotal += cost;
			
			Document item = new Document()
					.append(USER, id.getString(USER))
					.append(FIELD_DLAB_ID, resourceId)
					.append(DLAB_RESOURCE_TYPE, resourceTypeId)
					.append(SHAPE, shapeName)
					.append(FIELD_PRODUCT, id.getString(FIELD_PRODUCT))
					.append(FIELD_RESOURCE_TYPE, id.getString(FIELD_RESOURCE_TYPE))
					.append(FIELD_COST, cost)
					.append(FIELD_CURRENCY_CODE, id.getString(FIELD_CURRENCY_CODE))
					.append(USAGE_DATE_START, dateStart)
					.append(USAGE_DATE_END, dateEnd);
			reportItems.add(item);
		}
		
		return new Document()
				.append("service_base_name", settings.getServiceBaseName())
				.append("tag_resource_id", settings.getConfTagResourceId())
				.append(USAGE_DATE_START, usageDateStart)
				.append(USAGE_DATE_END, usageDateEnd)
				.append("lines", reportItems)
				.append("cost_total", BillingUtils.round(costTotal, 2))
				.append(FIELD_CURRENCY_CODE, (reportItems.size() > 0 ? reportItems.get(0).getString(FIELD_CURRENCY_CODE) : null));
    }
}