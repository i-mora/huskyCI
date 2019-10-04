// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package db

import (
	"fmt"
	"time"

	mongoHuskyCI "github.com/globocom/huskyCI/api/db/mongo"
	"github.com/globocom/huskyCI/api/util"
	"gopkg.in/mgo.v2/bson"
)

var statsQueryBase = map[string][]bson.M{
	"language":  generateSimpleAggr("codes", "language", "codes.language"),
	"container": generateSimpleAggr("containers", "container", "containers.securityTest.name"),
	"analysis": []bson.M{
		bson.M{
			"$project": bson.M{
				"finishedAt": 1,
				"result":     1,
			},
		},
		bson.M{
			"$group": bson.M{
				"_id": "$result",
				"count": bson.M{
					"$sum": 1,
				},
			},
		},
		bson.M{
			"$project": bson.M{
				"count":  1,
				"result": "$_id",
				"_id":    0,
			},
		},
	},
	"repository": []bson.M{
		bson.M{
			"$match": bson.M{
				"repositoryURL": bson.M{
					"$exists": true,
				},
			},
		},
		bson.M{
			"$match": bson.M{
				"repositoryBranch": bson.M{
					"$exists": true,
				},
			},
		},
		bson.M{
			"$group": bson.M{
				"_id": bson.M{
					"repositoryBranch": "$repositoryBranch",
					"repositoryURL":    "$repositoryURL",
				},
			},
		},
		bson.M{
			"$group": bson.M{
				"_id": bson.M{
					"repositoryURL": "$_id.repositoryURL",
				},
				"branches": bson.M{
					"$sum": 1,
				},
			},
		},
		bson.M{
			"$group": bson.M{
				"_id": "repositories",
				"totalBranches": bson.M{
					"$sum": "$branches",
				},
				"totalRepositories": bson.M{
					"$sum": 1,
				},
			},
		},
	},
	"author": []bson.M{
		bson.M{
			"$project": bson.M{
				"commitAuthors": 1,
			},
		},
		bson.M{
			"$unwind": "$commitAuthors",
		},
		bson.M{
			"$group": bson.M{
				"_id": "$commitAuthors",
			},
		},
		bson.M{
			"$group": bson.M{
				"_id": "commitAuthors",
				"totalAuthors": bson.M{
					"$sum": 1,
				},
			},
		},
	},
	"severity": []bson.M{
		bson.M{
			"$project": bson.M{
				"huskyresults": bson.M{
					"$objectToArray": "$huskyciresults",
				},
			},
		},
		bson.M{
			"$unwind": "$huskyresults",
		},
		bson.M{
			"$project": bson.M{
				"languageresults": bson.M{
					"$objectToArray": "$huskyresults.v",
				},
			},
		},
		bson.M{
			"$unwind": "$languageresults",
		},
		bson.M{
			"$project": bson.M{
				"results": bson.M{
					"$objectToArray": "$languageresults.v",
				},
			},
		},
		bson.M{
			"$unwind": "$results",
		},
		bson.M{
			"$group": bson.M{
				"_id": "$results.k",
				"count": bson.M{
					"$sum": bson.M{
						"$size": "$results.v",
					},
				},
			},
		},
		bson.M{
			"$project": bson.M{
				"severity": "$_id",
				"count":    1,
				"_id":      0,
			},
		},
	},
	"time-to-fix": []bson.M{
		bson.M{
			"$project": bson.M{
				"repositoryBranch": 1,
				"startedAt":        1,
				"finishedAt":       1,
				"result":           1,
				"repositoryURL":    1,
				"huskyciresults": bson.M{
					"$cond": bson.M{
						"if": bson.M{
							"$eq": []string{"{}", "$huskyciresults"},
						},
						"then": "$REMOVE",
						"else": "$huskyciresults",
					},
				},
			},
		}, bson.M{
			"$match": bson.M{
				"result": bson.M{
					"$in": []string{"passed", "failed"},
				},
			},
		}, bson.M{
			"$unwind": bson.M{
				"path":                       "$startedAt",
				"preserveNullAndEmptyArrays": false,
			},
		}, bson.M{
			"$unwind": bson.M{
				"path":                       "$finishedAt",
				"preserveNullAndEmptyArrays": false,
			},
		}, bson.M{
			"$unwind": bson.M{
				"path":                       "$huskyciresults",
				"preserveNullAndEmptyArrays": false,
			},
		}, bson.M{
			"$group": bson.M{
				"_id": bson.M{
					"repositoryURL":    "$repositoryURL",
					"repositoryBranch": "$repositoryBranch",
					"result":           "$result",
				},
				"data": bson.M{
					"$push": bson.M{
						"startedAt":      "$startedAt",
						"finishedAt":     "$finishedAt",
						"hunkyciresults": "$huskyciresults",
					},
				},
				"count": bson.M{
					"$sum": 1,
				},
			},
		}, bson.M{
			"$group": bson.M{
				"_id": bson.M{
					"repositoryURL":    "$_id.repositoryURL",
					"repositoryBranch": "$_id.repositoryBranch",
				},
				"analyses": bson.M{
					"$push": bson.M{
						"result": "$_id.result",
						"count":  "$count",
						"data":   "$data",
					},
				},
				"total": bson.M{
					"$sum": "$count",
				},
			},
		}, bson.M{
			"$match": bson.M{
				"analyses": bson.M{
					"$size": 2,
				},
			},
		}, bson.M{
			"$project": bson.M{
				"_id":              0,
				"repositoryURL":    "$_id.repositoryURL",
				"repositoryBranch": "$_id.repositoryBranch",
				"analyses":         1,
				"totalAnalyses":    1,
			},
		},
	},
}

// generateSimpleAggr generates an aggregation that counts each field group.
func generateSimpleAggr(field, finalName, groupID string) []bson.M {
	return []bson.M{
		bson.M{
			"$project": bson.M{
				field: 1,
			},
		},
		bson.M{
			"$unwind": fmt.Sprintf("$%s", field),
		},
		bson.M{
			"$group": bson.M{
				"_id": fmt.Sprintf("$%s", groupID),
				"count": bson.M{
					"$sum": 1,
				},
			},
		},
		bson.M{
			"$project": bson.M{
				finalName: "$_id",
				"count":   1,
				"_id":     0,
			},
		},
	}
}

// generateTimeFilterStage generates a stage that filter records by time range
func generateTimeFilterStage(rangeInitDays, rangeEndDays int) []bson.M {
	return []bson.M{
		bson.M{
			"$match": bson.M{
				"finishedAt": bson.M{
					"$gte": util.BeginningOfTheDay(time.Now().AddDate(0, 0, rangeInitDays)),
					"$lte": util.EndOfTheDay(time.Now().AddDate(0, 0, rangeEndDays)),
				},
			},
		},
	}
}

// TimeToFixData queries MongoDB and parse the result to consolidate time to fix vulnerability data
func TimeToFixData(query []bson.M) (interface{}, error) {
	result, err := mongoHuskyCI.Conn.Aggregation(query, mongoHuskyCI.AnalysisCollection)
	return result, err
}
