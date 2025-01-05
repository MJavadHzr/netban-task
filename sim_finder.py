import torch
from sql_queries import *
from sentence_transformers import SentenceTransformer


class SimFinder:
    def __init__(self, database, model_name, threshold):
        self.db = database
        self.model = SentenceTransformer(f"sentence-transformers/{model_name}")
        self.threshold = threshold
        self.groups = dict()  # ids -> group-num string

    def get_sims(self):
        # group records with cve
        not_null_cve = self.db.query(NOT_NULL_CVE_QUERY)
        self._group_cve(not_null_cve)

        # group records with null cve
        null_cve = self.db.query(NULL_CVE_QUERY)
        self._group_null_cve(null_cve)

        return self._group_to_dict()

    def _group_to_dict(self):
        output_dict = self.db.query(SELECT_QUERY.format(columns='*'), return_dict=True)
        for o in output_dict:
            o['tag'] = self.groups[o['id']]
        return output_dict

    def _group_cve(self, records):
        ids = [r[0] for r in records]
        groups = [r[1] for r in records]
        self.groups = dict(zip(ids, groups))

    def _group_null_cve(self, null_cve):
        null_ids = [r[0] for r in null_cve]

        all_desc = self.db.query(SELECT_QUERY.format(columns='id, title, description, endpoint'))
        idx_to_ids = [r[0] for r in all_desc]
        ids_to_idx = dict(zip(idx_to_ids, range(len(idx_to_ids))))

        sims = self._calculate_sims(null_ids, all_desc, ids_to_idx)
        self._team_up(null_ids, sims, idx_to_ids)
        self._assign_remaining(
            [id for id in null_ids if id not in self.groups.keys()])

    def _calculate_sims(self, null_ids, all_desc, ids_to_idx):
        all_desc_str = [f"Title: {r[1]}\nDescription: {r[2]}\nEnd-Point: {r[3]}" for r in all_desc]
        encodes = self.model.encode(all_desc_str)
        sims = self.model.similarity(encodes, encodes)
        sims = sims[[ids_to_idx[id] for id in null_ids], :]
        return sims

    def _team_up(self, null_ids, sims, idx_to_ids):
        for i, row in enumerate(sims):
            src_id = null_ids[i]
            found_match = None
            for j, value in enumerate(row):
                if value >= self.threshold:
                    target_id = idx_to_ids[j]
                    if src_id == target_id:
                        continue
                    if target_id in self.groups.keys():
                        found_match = target_id
                        break
            if found_match is None:
                new_group = f"group_{len(set(self.groups.values())) + 1}"
                self.groups[src_id] = new_group
            else:
                self.groups[src_id] = self.groups[target_id]

    def _assign_remaining(self, not_assigned_null_ids):
        if len(not_assigned_null_ids) == 0:
            return
        for id in not_assigned_null_ids:
            new_group = f"group_{len(set(self.groups.values()))+1}"
            self.groups[id] = new_group
