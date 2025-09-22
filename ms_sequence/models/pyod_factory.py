"""PYOD model factory."""
from typing import Any

from pyod.models.iforest import IForest
from pyod.models.copod import COPOD
from pyod.models.ecod import ECOD
from pyod.models.lof import LOF

# AutoEncoder 선택적 임포트
try:
    from pyod.models.auto_encoder import AutoEncoder
    HAS_AUTOENCODER = True
except ImportError:
    HAS_AUTOENCODER = False


class PyodModelFactory:
    """PYOD 모델 팩토리."""
    
    @staticmethod
    def create_model(name: str, **kwargs) -> Any:
        """
        PYOD 모델 생성.
        
        Args:
            name: 모델 이름 (IForest, COPOD, ECOD, LOF, AutoEncoder)
            **kwargs: 모델별 파라미터
            
        Returns:
            PYOD 모델 인스턴스
        """
        name = name.lower()
        
        # 기본 파라미터
        contamination = kwargs.get('contamination', 0.05)
        random_state = kwargs.get('random_state', 42)
        
        if name == "iforest":
            return IForest(
                n_estimators=kwargs.get('n_estimators', 400),
                contamination=contamination,
                random_state=random_state,
                behaviour="new"  # backward compatibility
            )
        
        elif name == "copod":
            return COPOD(contamination=contamination)
        
        elif name == "ecod":
            return ECOD(contamination=contamination)
        
        elif name == "lof":
            return LOF(
                contamination=contamination,
                n_neighbors=kwargs.get('n_neighbors', 20),
                novelty=False
            )
        
        elif name in ("autoencoder", "auto_encoder", "ae"):
            if not HAS_AUTOENCODER:
                raise RuntimeError("AutoEncoder requires PyTorch. Install torch first.")
            
            return AutoEncoder(
                contamination=contamination,
                epochs=kwargs.get('epochs', 15),
                batch_size=kwargs.get('batch_size', 64),
                hidden_neurons=None,  # auto-sizing
                verbose=1,
                random_state=random_state
            )
        
        else:
            raise ValueError(f"Unsupported model: {name}")