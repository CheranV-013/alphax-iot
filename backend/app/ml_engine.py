from pathlib import Path
import joblib, numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

FEATURES = ["amount", "velocity", "device_change", "location_change", "ip_risk", "spend_deviation", "hour"]

class MLEngine:
    def __init__(self, model_dir="models"):
        self.path = Path(model_dir); self.path.mkdir(exist_ok=True)
        self.iso = self._load_or_train("isolation.joblib", self._train_iso)
        self.classifier = self._load_or_train("fraud_classifier.joblib", self._train_classifier)

    def _load_or_train(self, filename, fn):
        path = self.path / filename
        if path.exists(): return joblib.load(path)
        model = fn(); joblib.dump(model, path); return model

    def _data(self):
        rng = np.random.default_rng(42); n = 1400
        x = np.column_stack([rng.lognormal(4.2, 0.65, n), rng.poisson(2, n)+1, rng.binomial(1,.18,n), rng.exponential(1.0,n), rng.beta(1.4,5,n), rng.normal(0,1,n), rng.integers(0,24,n)])
        y = ((x[:,0]>220) | (x[:,1]>7) | (x[:,2]==1) | (x[:,3]>2.5) | (x[:,4]>.72) | (abs(x[:,5])>2.2)).astype(int)
        return x, y

    def _train_iso(self):
        x,_ = self._data(); return IsolationForest(n_estimators=160, contamination=.12, random_state=42).fit(x)
    def _train_classifier(self):
        x,y = self._data(); return RandomForestClassifier(n_estimators=140, max_depth=8, random_state=42, class_weight="balanced").fit(x,y)
    def infer(self, features):
        x = np.array([[features[k] for k in FEATURES]])
        fraud = float(self.classifier.predict_proba(x)[0,1])
        raw = float(self.iso.decision_function(x)[0]); anomaly = float(np.clip((0.15-raw)/0.3,0,1))
        return fraud, anomaly
    def metrics(self):
        x,y=self._data(); xt,xv,yt,yv=train_test_split(x,y,test_size=.25,random_state=42,stratify=y); m=RandomForestClassifier(n_estimators=140,max_depth=8,random_state=42,class_weight="balanced").fit(xt,yt); p=m.predict(xv); pro=m.predict_proba(xv)[:,1]
        return {"accuracy":round(accuracy_score(yv,p),3),"precision":round(precision_score(yv,p),3),"recall":round(recall_score(yv,p),3),"f1":round(f1_score(yv,p),3),"roc_auc":round(roc_auc_score(yv,pro),3),"label":"Prototype evaluation on synthetic/demo dataset"}

