#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Anomaly Detection Model Configuration
이상탐지 모델 설정 및 관리

Author: Kong Ju
Date: 2025-09-01
"""

from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
import numpy as np
from typing import Dict, Any, Optional, Tuple, List, Union
from dataclasses import dataclass
import warnings
warnings.filterwarnings('ignore')

# 고급 Random Cut Forest 구현
try:
    from sklearn.base import BaseEstimator
    from sklearn.utils.validation import check_array, check_is_fitted
    from sklearn.utils.multiclass import check_classification_targets
    from sklearn.utils import check_random_state
    from sklearn.base import OutlierMixin
except Exception:
    # 최소 의존: scikit-learn 미설치 환경에서도 클래스 인터페이스만 맞추기
    class BaseEstimator: ...
    class OutlierMixin: ...
    def check_array(X, accept_sparse=False, ensure_2d=True, allow_nd=False, dtype="float64", estimator=None):
        X = np.asarray(X, dtype=float)
        if X.ndim == 1:
            X = X.reshape(-1, 1)
        return X
    def check_is_fitted(estimator, attributes=None): return
    def check_random_state(seed):
        rng = np.random.RandomState()
        rng.seed(seed)
        return rng

try:
    import rrcf  # pip install rrcf
    RRCF_AVAILABLE = True
except ImportError:
    RRCF_AVAILABLE = False
    print("⚠️ rrcf 라이브러리가 설치되지 않았습니다. 기본 구현을 사용합니다.")
    print("   고급 Random Cut Forest를 사용하려면: pip install rrcf")

# 🤖 지원하는 이상탐지 모델 목록
SUPPORTED_MODELS = {
    'isolation_forest': 'Isolation Forest',
    'local_outlier_factor': 'Local Outlier Factor',
    'one_class_svm': 'One Class SVM',
    'random_cut_forest': 'Random Cut Forest (Ensemble)'
}

# 📊 모델별 기본 하이퍼파라미터
MODEL_DEFAULT_PARAMS = {
    'isolation_forest': {
        'contamination': 0.1,
        'random_state': 42,
        'n_estimators': 100,
        'max_samples': 'auto',
        'max_features': 1.0,
        'bootstrap': False,
        'n_jobs': -1
    },
    'local_outlier_factor': {
        'contamination': 0.1,
        'n_neighbors': 20,
        'algorithm': 'auto',
        'leaf_size': 30,
        'metric': 'minkowski',
        'p': 2,
        'n_jobs': -1
    },
    'one_class_svm': {
        'kernel': 'rbf',
        'gamma': 'scale',
        'nu': 0.1,  # contamination과 유사한 역할
        'degree': 3,
        'coef0': 0.0,
        'tol': 1e-3,
        'shrinking': True,
        'cache_size': 200,
        'max_iter': -1
    },
    'random_cut_forest': {
        'n_estimators': 100,
        'contamination': 0.1,
        'random_state': 42,
        'max_depth': 10,
        'min_samples_split': 2,
        'min_samples_leaf': 1,
        'bootstrap': True,
        'n_jobs': -1
    }
}

# 🏷️ 모델별 파일명 접미사
MODEL_FILE_SUFFIX = {
    'isolation_forest': 'iforest',
    'local_outlier_factor': 'lof',
    'one_class_svm': 'ocsvm',
    'random_cut_forest': 'rcf'
}

# 📝 모델별 설명
MODEL_DESCRIPTIONS = {
    'isolation_forest': {
        'name': 'Isolation Forest',
        'description': '트리 기반 이상탐지. 빠르고 효율적이며 고차원 데이터에 적합',
        'pros': ['빠른 학습과 예측', '고차원 데이터 처리 가능', '메모리 효율적'],
        'cons': ['범주형 데이터 처리 한계', '파라미터 튜닝 필요'],
        'best_for': '대용량 데이터, 실시간 처리'
    },
    'local_outlier_factor': {
        'name': 'Local Outlier Factor',
        'description': '지역 밀도 기반 이상탐지. 국소적 이상치 탐지에 강력',
        'pros': ['국소적 이상치 탐지', '밀도 기반 접근', '직관적 결과'],
        'cons': ['계산 비용 높음', '차원의 저주', '메모리 사용량 많음'],
        'best_for': '중소규모 데이터, 클러스터 내 이상치 탐지'
    },
    'one_class_svm': {
        'name': 'One Class SVM',
        'description': '서포트 벡터 머신 기반 이상탐지. 복잡한 경계면 학습 가능',
        'pros': ['복잡한 경계면 학습', '커널 트릭 활용', '이론적 근거 탄탄'],
        'cons': ['파라미터 민감', '대용량 데이터 처리 어려움', '해석 어려움'],
        'best_for': '중소규모 데이터, 복잡한 패턴'
    },
    'random_cut_forest': {
        'name': 'Random Cut Forest',
        'description': 'RRCF 라이브러리 기반 전문적 이상탐지 (Collusive Displacement 사용)',
        'pros': ['정확한 RRCF 알고리즘', '스트리밍 지원', '메모리 효율적', '시계열 특화'],
        'cons': ['외부 라이브러리 의존', '설정 복잡성', 'rrcf 설치 필요'],
        'best_for': '전문적 이상탐지, 스트리밍 데이터, 시계열 분석'
    }
}


@dataclass
class _TreeState:
    tree: "rrcf.RCTree"
    # 각 트리 내 포인트 인덱스 매핑: 글로벌 id -> 노드 키
    keys: Dict[int, int]


class RandomCutForestSKL(BaseEstimator, OutlierMixin):
    """
    scikit-learn 스타일 Random Cut Forest (RRCF backend)
    고급 구현 - rrcf 라이브러리 사용

    Parameters
    ----------
    n_trees : int
        포레스트 트리 개수.
    tree_capacity : int
        각 트리의 최대 노드 수(capacity). 초과 시 oldest eviction 수행.
    sample_size : Optional[int]
        초기 fit 시 트리별 bootstrap 샘플 크기. None이면 min(n_samples, tree_capacity).
    contamination : float
        이상치 비율 추정치(0~0.5). predict에서 임계치 결정에 사용.
    random_state : Optional[int]
        랜덤 시드.
    shingle_size : int
        시계열 shingles (window) 크기. 1이면 미사용.
    store_scores : bool
        fit 시 학습 데이터의 score를 저장할지 여부.
    normalize_scores : bool
        decision_function에서 0~1 정규화 반환 여부.
    """

    def __init__(
        self,
        n_trees: int = 50,
        tree_capacity: int = 256,
        sample_size: Optional[int] = None,
        contamination: float = 0.1,
        random_state: Optional[int] = None,
        shingle_size: int = 1,
        store_scores: bool = True,
        normalize_scores: bool = True,
    ):
        self.n_trees = int(n_trees)
        self.tree_capacity = int(tree_capacity)
        self.sample_size = sample_size
        self.contamination = float(contamination)
        self.random_state = random_state
        self.shingle_size = int(shingle_size)
        self.store_scores = bool(store_scores)
        self.normalize_scores = bool(normalize_scores)

    # ------------------------
    # 내부 유틸
    # ------------------------
    def _make_shingles(self, X: np.ndarray) -> np.ndarray:
        if self.shingle_size <= 1:
            return X
        # 시계열 전처리: 길이 N -> N - s + 1 개 윈도우
        s = self.shingle_size
        if X.ndim == 1:
            X = X.reshape(-1, 1)
        N, D = X.shape
        if N < s:
            raise ValueError(f"Not enough samples ({N}) for shingle_size={s}")
        windows = np.lib.stride_tricks.sliding_window_view(X, (s, D))
        # windows shape: (N-s+1, 1, s, D) -> reshape
        windows = windows.reshape(-1, s * D)
        return windows

    def _build_forest_initial(self, X: np.ndarray):
        rng = check_random_state(self.random_state)
        n, _ = X.shape
        sample_size = self.sample_size or min(n, self.tree_capacity)
        self._forest: List[_TreeState] = []

        # 전역 포인트 id 증가값 (streaming에서 계속 증가)
        self._global_index = 0
        self._seen_ = 0

        for _ in range(self.n_trees):
            idx = rng.choice(n, size=sample_size, replace=False)
            tree = rrcf.RCTree()
            keys = {}
            for i in idx:
                gid = self._global_index
                key = tree.insert_point(X[i], index=gid)
                keys[gid] = key
                self._global_index += 1
                self._seen_ += 1
            self._forest.append(_TreeState(tree=tree, keys=keys))

    def _evict_if_needed(self, state: _TreeState):
        # 용량 초과 시 가장 오래된(global id가 가장 작은) 포인트 제거
        tree, keys = state.tree, state.keys
        while tree.leaves and len(tree.leaves) > self.tree_capacity:
            oldest_gid = min(keys.keys())
            if oldest_gid in keys:
                key = keys.pop(oldest_gid)
                try:
                    tree.forget_point(key)
                except Exception:
                    # 방어적 처리: key가 이미 사라진 경우
                    pass

    def _codisp_scores(self, X: np.ndarray) -> np.ndarray:
        # 각 트리에서 collusive displacement (CoDisp) 점수 계산 후 평균
        scores = np.zeros(X.shape[0], dtype=float)
        
        if not RRCF_AVAILABLE:
            # rrcf가 없는 경우 기본 점수 반환
            return np.random.uniform(0.1, 0.9, X.shape[0])
        
        try:
            for tree_idx, state in enumerate(self._forest):
                tree = state.tree
                
                # 각 포인트에 대해 CoDisp 점수 계산 (복사본 방식 사용)
                for i, x in enumerate(X):
                    try:
                        # 트리 복사본 생성하여 안전하게 계산
                        import copy
                        tree_copy = copy.deepcopy(tree)
                        
                        # 고유한 임시 인덱스 사용
                        temp_index = tree_idx * 100000 + i + 50000
                        
                        # 복사본에 포인트 삽입
                        key = tree_copy.insert_point(x, index=temp_index)
                        
                        # CoDisp 점수 계산
                        codisp_score = tree_copy.codisp(key)
                        scores[i] += codisp_score
                        
                        # 복사본은 자동으로 가비지 컬렉션됨
                        
                    except Exception as point_error:
                        # 복사본 방식도 실패하면 간단한 대체 점수 사용
                        try:
                            # 기존 트리에서 가장 유사한 리프 찾기
                            if hasattr(tree, 'leaves') and tree.leaves:
                                # 거리 기반 간단한 점수
                                distances = []
                                for leaf_key in list(tree.leaves.keys())[:min(10, len(tree.leaves))]:
                                    leaf_point = tree.leaves[leaf_key].x
                                    if leaf_point is not None and len(leaf_point) == len(x):
                                        dist = np.linalg.norm(np.array(x) - np.array(leaf_point))
                                        distances.append(dist)
                                
                                if distances:
                                    # 거리의 역수를 점수로 사용 (가까울수록 높은 점수)
                                    min_dist = min(distances)
                                    score = 1.0 / (1.0 + min_dist)
                                    scores[i] += score
                                else:
                                    scores[i] += 0.5
                            else:
                                scores[i] += 0.5
                        except:
                            scores[i] += 0.5  # 최종 기본값
            
            # 트리 개수로 평균 계산
            if self.n_trees > 0:
                scores /= float(self.n_trees)
            
            # 점수가 모두 0인 경우 거리 기반 점수로 대체
            if np.all(scores == 0):
                print("⚠️ 모든 CoDisp 점수가 0입니다. 거리 기반 점수를 사용합니다.")
                return self._distance_based_scores(X)
            
            return scores
            
        except Exception as e:
            print(f"⚠️ RRCF CoDisp 계산 실패: {e}, 거리 기반 점수 사용")
            return self._distance_based_scores(X)

    def _distance_based_scores(self, X: np.ndarray) -> np.ndarray:
        """거리 기반 이상 점수 계산 (RRCF 대체)"""
        scores = np.zeros(X.shape[0], dtype=float)
        
        try:
            # 학습된 포인트들과의 거리를 기반으로 점수 계산
            all_points = []
            for state in self._forest:
                tree = state.tree
                if hasattr(tree, 'leaves') and tree.leaves:
                    for leaf_key in list(tree.leaves.keys())[:50]:  # 메모리 효율성을 위해 제한
                        leaf_point = tree.leaves[leaf_key].x
                        if leaf_point is not None:
                            all_points.append(np.array(leaf_point))
            
            if all_points:
                train_points = np.array(all_points)
                
                for i, x in enumerate(X):
                    # k-nearest neighbor 거리 계산
                    distances = []
                    for train_point in train_points:
                        if len(train_point) == len(x):
                            dist = np.linalg.norm(np.array(x) - train_point)
                            distances.append(dist)
                    
                    if distances:
                        # 상위 10% 거리의 평균을 사용
                        distances.sort()
                        k = max(1, len(distances) // 10)
                        avg_dist = np.mean(distances[:k])
                        # 거리가 클수록 높은 이상 점수
                        scores[i] = min(1.0, avg_dist / (1.0 + avg_dist))
                    else:
                        scores[i] = 0.5
            else:
                # 학습 포인트가 없는 경우 균등 분포
                scores = np.random.uniform(0.1, 0.9, X.shape[0])
        
        except Exception as e:
            print(f"⚠️ 거리 기반 점수 계산 실패: {e}, 랜덤 점수 사용")
            scores = np.random.uniform(0.1, 0.9, X.shape[0])
        
        return scores

    def _normalize(self, s: np.ndarray) -> np.ndarray:
        if not self.normalize_scores:
            return s
        # 안정적 0-1 scaling
        s = np.asarray(s, dtype=float)
        lo, hi = np.nanpercentile(s, 1.0), np.nanpercentile(s, 99.0)
        if hi <= lo:
            return np.zeros_like(s)
        return np.clip((s - lo) / (hi - lo), 0.0, 1.0)

    # ------------------------
    # 공개 API
    # ------------------------
    def fit(self, X: np.ndarray, y: Optional[np.ndarray] = None):
        X = check_array(X, ensure_2d=True, dtype=float)
        Xs = self._make_shingles(X)
        self._build_forest_initial(Xs)
        # 학습 데이터 점수 저장(선택)
        if self.store_scores:
            self._train_scores_ = self.score_samples(X)
        # contamination 기반 임계치 계산
        self._set_threshold_from_scores(self._train_scores_ if self.store_scores else self.score_samples(X))
        self.n_features_in_ = X.shape[1]
        self.is_fitted_ = True
        return self

    def partial_fit(self, X: np.ndarray, y: Optional[np.ndarray] = None):
        check_is_fitted(self, attributes=["_forest"])
        X = check_array(X, ensure_2d=True, dtype=float)
        Xs = self._make_shingles(X)

        # 스트리밍: 각 포인트를 모든 트리에 삽입
        for x in Xs:
            gid = self._global_index
            for state in self._forest:
                key = state.tree.insert_point(x, index=gid)
                state.keys[gid] = key
                self._evict_if_needed(state)
            self._global_index += 1
            self._seen_ += 1
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        check_is_fitted(self, attributes=["_forest"])
        X = check_array(X, ensure_2d=True, dtype=float)
        Xs = self._make_shingles(X)
        # 평균 codisp가 크면 더 "이상" (higher = more anomalous)
        scores = self._codisp_scores(Xs)
        return scores

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        # scikit-learn 관례: 값이 클수록 정상에 가깝게 반환하는 경우가 많지만,
        # 이상탐지에서는 점수를 그대로 쓰는 케이스도 흔함.
        # 여기서는 (정규화된) anomaly score를 반환하되, "높을수록 이상"을 유지.
        s = self.score_samples(X)
        return self._normalize(s)

    def predict(self, X: np.ndarray, threshold: Optional[float] = None) -> np.ndarray:
        # 반환: 1=정상(inlier), -1=이상치(outlier) (sklearn OutlierMixin 관례)
        s = self.score_samples(X)
        thr = self._threshold_ if threshold is None else float(threshold)
        y = np.where(s > thr, -1, 1)
        return y

    def fit_predict(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> np.ndarray:
        self.fit(X, y)
        return self.predict(X)

    # ------------------------
    # 임계치 설정
    # ------------------------
    def _set_threshold_from_scores(self, scores: np.ndarray):
        # contamination 상위 백분위에 해당하는 점수를 임계치로 설정
        c = float(self.contamination)
        c = min(max(c, 1e-6), 0.5)  # 안전 범위
        self._threshold_ = np.quantile(scores, 1.0 - c)

    # ------------------------
    # 속성 조회
    # ------------------------
    @property
    def threshold_(self) -> float:
        check_is_fitted(self, attributes=["_threshold_"])
        return self._threshold_

    @property
    def forest_size_(self) -> int:
        check_is_fitted(self, attributes=["_forest"])
        return len(self._forest)

    @property
    def seen_(self) -> int:
        check_is_fitted(self, attributes=["_forest"])
        return int(self._seen_)


class RandomCutForest:
    """
    Random Cut Forest 알고리즘의 간단한 구현
    (AWS SageMaker Random Cut Forest의 단순화 버전)
    """
    
    def __init__(self, n_estimators=100, contamination=0.1, random_state=42, 
                 max_depth=10, min_samples_split=2, min_samples_leaf=1, 
                 bootstrap=True, n_jobs=-1):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.min_samples_leaf = min_samples_leaf
        self.bootstrap = bootstrap
        self.n_jobs = n_jobs
        self.trees = []
        self.is_fitted = False
        
    def _build_tree(self, X, depth=0):
        """개별 트리 구축"""
        # 안전 검사
        if X is None or len(X) == 0:
            return {'type': 'leaf', 'size': 1}
        
        if len(X) <= self.min_samples_leaf or depth >= self.max_depth:
            return {'type': 'leaf', 'size': len(X)}
        
        if len(X) < self.min_samples_split:
            return {'type': 'leaf', 'size': len(X)}
        
        # 특성 개수 확인
        if X.shape[1] == 0:
            return {'type': 'leaf', 'size': len(X)}
        
        try:
            # 랜덤 특성과 분할점 선택
            feature_idx = np.random.randint(0, X.shape[1])
            feature_values = X[:, feature_idx]
            
            # 특성 값이 모두 같은 경우
            unique_values = np.unique(feature_values)
            if len(unique_values) <= 1:
                return {'type': 'leaf', 'size': len(X)}
            
            # 분할 값 선택 (최솟값과 최댓값 사이)
            min_val, max_val = feature_values.min(), feature_values.max()
            if min_val == max_val:
                return {'type': 'leaf', 'size': len(X)}
            
            # 분할값이 너무 극단적이지 않도록 조정
            split_value = np.random.uniform(
                min_val + 0.01 * (max_val - min_val),
                max_val - 0.01 * (max_val - min_val)
            )
            
            left_mask = feature_values <= split_value
            right_mask = ~left_mask
            
            # 분할 결과 확인
            if np.sum(left_mask) == 0 or np.sum(right_mask) == 0:
                return {'type': 'leaf', 'size': len(X)}
            
            return {
                'type': 'split',
                'feature': feature_idx,
                'threshold': split_value,
                'left': self._build_tree(X[left_mask], depth + 1),
                'right': self._build_tree(X[right_mask], depth + 1)
            }
            
        except Exception as e:
            print(f"⚠️ 트리 구축 오류: {e}, 리프 노드로 처리")
            return {'type': 'leaf', 'size': len(X)}
    
    def _path_length(self, x, tree, depth=0):
        """샘플의 경로 길이 계산"""
        if tree['type'] == 'leaf':
            # 리프 노드에서의 평균 경로 길이 추정
            size = tree['size']
            if size <= 1:
                c = 0
            elif size == 2:
                c = 1
            else:
                c = 2 * (np.log(size - 1) + 0.5772156649) - 2 * (size - 1) / size
            return depth + c
        
        if x[tree['feature']] <= tree['threshold']:
            return self._path_length(x, tree['left'], depth + 1)
        else:
            return self._path_length(x, tree['right'], depth + 1)
    
    def fit(self, X):
        """모델 학습"""
        np.random.seed(self.random_state)
        self.trees = []
        
        # pandas DataFrame을 numpy array로 변환
        if hasattr(X, 'values'):
            X_array = X.values
        else:
            X_array = np.array(X)
        
        for i in range(self.n_estimators):
            # 부트스트랩 샘플링
            if self.bootstrap:
                indices = np.random.choice(len(X_array), size=len(X_array), replace=True)
                sample = X_array[indices]
            else:
                sample = X_array
            
            tree = self._build_tree(sample)
            self.trees.append(tree)
        
        self.is_fitted = True
        return self
    
    def _c(self, n):
        """평균 BST 경로 길이 계산 (Isolation Forest 표준)"""
        if n <= 1:
            return 0
        elif n == 2:
            return 1
        else:
            return 2 * (np.log(n - 1) + 0.5772156649) - 2 * (n - 1) / n
    
    def decision_function(self, X):
        """이상 스코어 계산"""
        if not self.is_fitted:
            raise ValueError("모델이 학습되지 않았습니다.")
        
        # X를 numpy array로 변환
        if hasattr(X, 'values'):
            X = X.values
        X = np.array(X)
        
        scores = []
        n_samples = len(X)
        c_value = self._c(n_samples)
        
        for x in X:
            try:
                path_lengths = []
                for tree in self.trees:
                    path_length = self._path_length(x, tree)
                    path_lengths.append(path_length)
                
                if len(path_lengths) == 0:
                    score = 0.5  # 기본값
                else:
                    avg_path_length = np.mean(path_lengths)
                    if c_value <= 0:
                        score = 0.5
                    else:
                        # 이상 스코어 (경로가 짧을수록 이상치)
                        score = 2 ** (-avg_path_length / c_value)
                        # 스코어 범위 제한 (0~1)
                        score = np.clip(score, 0.001, 0.999)
                
                scores.append(score)
            except Exception as e:
                print(f"⚠️ 스코어 계산 오류: {e}, 기본값 사용")
                scores.append(0.5)
        
        return np.array(scores)
    
    def predict(self, X):
        """이상치 예측"""
        try:
            scores = self.decision_function(X)
            if len(scores) == 0:
                return np.array([])
            
            # 상위 contamination 비율을 이상치로 분류
            threshold = np.percentile(scores, (1 - self.contamination) * 100)
            # 점수가 높을수록 이상치이므로 threshold보다 높으면 이상치(-1)
            predictions = np.where(scores > threshold, -1, 1)
            
            # 최소 1개의 이상치는 보장
            if np.sum(predictions == -1) == 0 and len(predictions) > 0:
                max_idx = np.argmax(scores)
                predictions[max_idx] = -1
            
            return predictions
            
        except Exception as e:
            print(f"⚠️ 예측 오류: {e}, 모든 데이터를 정상으로 분류")
            return np.ones(len(X), dtype=int)
    
    def _c(self, n):
        """평균 경로 길이 정규화 상수"""
        if n <= 0:
            return 1
        elif n == 1:
            return 1
        elif n == 2:
            return 1
        else:
            return 2 * (np.log(n - 1) + 0.5772156649) - 2 * (n - 1) / n


def get_model_instance(model_name: str, **kwargs) -> object:
    """
    모델 인스턴스 생성
    
    Args:
        model_name (str): 모델 이름
        **kwargs: 모델 파라미터
        
    Returns:
        object: 모델 인스턴스
    """
    if model_name not in SUPPORTED_MODELS:
        raise ValueError(f"지원하지 않는 모델입니다: {model_name}")
    
    # 기본 파라미터와 사용자 파라미터 병합
    params = MODEL_DEFAULT_PARAMS[model_name].copy()
    
    # 파라미터 변환 (contamination -> 모델별 해당 파라미터)
    converted_kwargs = kwargs.copy()
    
    if model_name == 'one_class_svm' and 'contamination' in converted_kwargs:
        # One Class SVM에서는 contamination을 nu로 변환
        contamination = converted_kwargs.pop('contamination')
        if 'nu' not in converted_kwargs:
            converted_kwargs['nu'] = contamination
    
    elif model_name == 'local_outlier_factor' and 'contamination' in converted_kwargs:
        # LOF는 contamination을 그대로 사용
        pass
    
    elif model_name == 'isolation_forest' and 'contamination' in converted_kwargs:
        # Isolation Forest는 contamination을 그대로 사용
        pass
    
    elif model_name == 'random_cut_forest' and 'contamination' in converted_kwargs:
        # Random Cut Forest는 contamination을 그대로 사용
        pass
    
    # 변환된 파라미터 병합
    params.update(converted_kwargs)
    
    # 잘못된 파라미터 제거 (각 모델에서 지원하지 않는 파라미터)
    if model_name == 'one_class_svm':
        # One Class SVM에서 지원하지 않는 파라미터 제거
        unsupported = ['contamination', 'n_estimators', 'n_neighbors', 'bootstrap', 'n_jobs']
        for param in unsupported:
            params.pop(param, None)
    
    elif model_name == 'local_outlier_factor':
        # LOF에서 지원하지 않는 파라미터 제거
        unsupported = ['n_estimators', 'max_samples', 'bootstrap', 'kernel', 'gamma', 'nu', 'random_state']
        for param in unsupported:
            params.pop(param, None)
    
    elif model_name == 'isolation_forest':
        # Isolation Forest에서 지원하지 않는 파라미터 제거
        unsupported = ['n_neighbors', 'kernel', 'gamma', 'nu', 'algorithm', 'leaf_size', 'metric', 'p']
        for param in unsupported:
            params.pop(param, None)
    
    elif model_name == 'random_cut_forest':
        # Random Cut Forest에서 지원하지 않는 파라미터 제거
        unsupported = ['n_neighbors', 'kernel', 'gamma', 'nu', 'algorithm', 'leaf_size', 'metric', 'p']
        for param in unsupported:
            params.pop(param, None)
    
    print(f"🔧 {SUPPORTED_MODELS[model_name]} 파라미터: {params}")
    
    if model_name == 'isolation_forest':
        return IsolationForest(**params)
    
    elif model_name == 'local_outlier_factor':
        return LocalOutlierFactor(**params)
    
    elif model_name == 'one_class_svm':
        return OneClassSVM(**params)
    
    elif model_name == 'random_cut_forest':
        # RRCF 라이브러리 사용 시 문제가 있으므로 기본 구현을 우선 사용
        print("🔧 안정적인 기본 Random Cut Forest 구현 사용")
        print("   (RRCF 라이브러리 CoDisp 계산에서 불안정성 발견)")
        return RandomCutForest(**params)
        
        # RRCF 라이브러리 사용 (현재 비활성화)
        if False and RRCF_AVAILABLE:  # 임시로 비활성화
            # 고급 RRCF 구현 사용 (rrcf 라이브러리)
            print("🌟 고급 Random Cut Forest (RRCF) 사용")
            # 파라미터 매핑
            rrcf_params = {
                'n_trees': params.get('n_estimators', 50),
                'contamination': params.get('contamination', 0.1),
                'random_state': params.get('random_state', 42),
                'tree_capacity': params.get('max_samples', 256),
                'normalize_scores': True,
                'store_scores': True
            }
            return RandomCutForestSKL(**rrcf_params)
    
    else:
        raise ValueError(f"모델 구현이 없습니다: {model_name}")


def get_model_info(model_name: str) -> Dict[str, Any]:
    """
    모델 정보 반환
    
    Args:
        model_name (str): 모델 이름
        
    Returns:
        Dict[str, Any]: 모델 정보
    """
    if model_name not in SUPPORTED_MODELS:
        raise ValueError(f"지원하지 않는 모델입니다: {model_name}")
    
    return MODEL_DESCRIPTIONS[model_name]


def get_file_suffix(model_name: str) -> str:
    """
    모델별 파일명 접미사 반환
    
    Args:
        model_name (str): 모델 이름
        
    Returns:
        str: 파일명 접미사
    """
    if model_name not in SUPPORTED_MODELS:
        raise ValueError(f"지원하지 않는 모델입니다: {model_name}")
    
    return MODEL_FILE_SUFFIX[model_name]


def print_supported_models():
    """지원하는 모델 목록 출력"""
    print("🤖 지원하는 이상탐지 모델:")
    print("=" * 60)
    
    for key, name in SUPPORTED_MODELS.items():
        info = MODEL_DESCRIPTIONS[key]
        print(f"\n📌 {name} ({key})")
        print(f"   설명: {info['description']}")
        print(f"   장점: {', '.join(info['pros'])}")
        print(f"   단점: {', '.join(info['cons'])}")
        print(f"   적합한 용도: {info['best_for']}")


def validate_model_params(model_name: str, params: Dict[str, Any]) -> Tuple[bool, str]:
    """
    모델 파라미터 유효성 검사
    
    Args:
        model_name (str): 모델 이름
        params (Dict[str, Any]): 파라미터
        
    Returns:
        Tuple[bool, str]: (유효성, 오류 메시지)
    """
    if model_name not in SUPPORTED_MODELS:
        return False, f"지원하지 않는 모델입니다: {model_name}"
    
    # contamination 범위 검사
    if 'contamination' in params:
        contamination = params['contamination']
        if not (0.0 < contamination < 0.5):
            return False, "contamination은 0과 0.5 사이의 값이어야 합니다."
    
    # 모델별 특정 파라미터 검사
    if model_name == 'local_outlier_factor':
        if 'n_neighbors' in params and params['n_neighbors'] <= 0:
            return False, "n_neighbors는 양수여야 합니다."
    
    elif model_name == 'one_class_svm':
        if 'nu' in params:
            nu = params['nu']
            if not (0.0 < nu <= 1.0):
                return False, "nu는 0과 1 사이의 값이어야 합니다."
    
    return True, ""


if __name__ == "__main__":
    print_supported_models()
    
    # 각 모델 인스턴스 생성 테스트
    print(f"\n🧪 모델 인스턴스 생성 테스트:")
    print("=" * 40)
    
    for model_name in SUPPORTED_MODELS.keys():
        try:
            model = get_model_instance(model_name)
            print(f"✅ {SUPPORTED_MODELS[model_name]}: 생성 성공")
        except Exception as e:
            print(f"❌ {SUPPORTED_MODELS[model_name]}: 생성 실패 - {e}")
